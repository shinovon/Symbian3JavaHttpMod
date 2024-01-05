package com.nokia.mj.impl.gcf.protocol.http;

/*
 * Licensed Materials - Property of IBM,
 * (c) Copyright IBM Corp. 2000, 2006  All Rights Reserved
 */

import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import javax.microedition.io.*;
import com.ibm.oti.connection.*;
import com.ibm.oti.util.Util;
import com.ibm.oti.connection.http.Header;

/**
 * Implements a HTTP connection. The value of the timeout argument is passed to
 * the socket connection. Use setConnectionParameters() to set the following parameters:
 * <UL>
 * <LI>proxy - set the proxy host, i.e. www.proxy.com:8080</LI>
 * <LI>httpversion - 0/1, set the HTTP version, the default is HTTP 1.1</LI>
 * <LI>followredirects - true/false, automatically follow redirects, the default
 * is true</LI>
 * <LI>chunked - true/false, send output in chunked format, HTTP 1.1 only,
 * the default is false</LI>
 * </UL>
 *
 * @author		OTI
 * @version		initial
 *
 * @see		javax.microedition.io.StreamConnection
 */
public class HttpConnectionPatched extends DataConnection implements CreateConnection, StreamConnection, HttpConnection {
	static final String GET = "GET";
	static final String HEAD = "HEAD";
	static final String POST = "POST";

	static final int HTTP_OK = 200;
	static final int HTTP_NO_CONTENT = 204;
	static final int HTTP_MULT_CHOICE = 300;
	static final int HTTP_MOVED_PERM = 301;
	static final int HTTP_MOVED_TEMP = 302;
	static final int HTTP_SEE_OTHER = 303;
	static final int HTTP_NOT_MODIFIED = 304;
	static final int HTTP_USE_PROXY = 305;
	static final int HTTP_BAD_REQUEST = 400;

	private static final int UNOPENED = 0, OPEN = 1, CLOSED = 2;

	int access;
	String host, file;
	int httpVersion = 1;	// Assume HTTP/1.1
	boolean sentRequest = false;
	boolean conClosed = false;
	String method = GET;	// request method, DEFAULT: "GET"
	int responseCode = -1;	// response code obtained from the request
	String responseMessage;	// response message corresponds to the response code
	// request header that will be sent to the server
	Header reqHeader = new Header(false);
	// response header received from the server
	Header resHeader;
	boolean timeout;
	InputStream is, uis;
	OutputStream socketOut;
	HttpOutputStream os;
	String proxyName;
	int port, proxyPort;
	boolean followRedirects = true;
	boolean sendChunked = false;
	String socketOptions = ""; //$NON-NLS-1$
	StreamConnection socket;
	boolean connected = false;
	private int inputStatus = UNOPENED, outputStatus = UNOPENED;

	private int nokiaTimeout = -1;
	private boolean j9socket = true;
	private String apn = "";

	private final class LimitedInputStream extends InputStream {
		int bytesRemaining;
	/**
	 * @param 		length
	 */
	public LimitedInputStream(int length) {
		bytesRemaining = length;
	}
	/**
	 * @see 		java.io.InputStream#close()
	 */
	public void close() throws IOException {
		bytesRemaining = 0;
		closeSocket();
	}
	/**
	 * @see 		java.io.InputStream#available()
	 */
	public int available() throws IOException {
		int result = is.available();
		if (result > bytesRemaining) return bytesRemaining;
		return result;
	}
	/**
	 * @see 		java.io.InputStream#read()
	 */
	public int read() throws IOException {
		if (bytesRemaining <= 0) return -1;
		int result = is.read();
		bytesRemaining--;
		return result;
	}
	/**
	 * @see 		java.io.InputStream#read(byte[], int, int)
	 */
	public int read(byte[] buf, int offset, int length) throws IOException {
		if (buf == null) throw new NullPointerException();
		// avoid int overflow
		if (offset < 0 || length < 0 || offset > buf.length || buf.length - offset < length)
			throw new ArrayIndexOutOfBoundsException();
		if (bytesRemaining <= 0) return -1;
		if (length > bytesRemaining) length = bytesRemaining;
		int result = is.read(buf, offset, length);
		if (result > 0) bytesRemaining -= result;
		return result;
	}
	/**
	 * @param 		amount
	 * @return		the result
	 *
	 * @throws 		IOException
	 */
	public long skip(long amount) throws IOException {
		if (bytesRemaining <= 0) return -1;
		if (amount > bytesRemaining) amount = bytesRemaining;
		long result = is.skip(amount);
		if (result > 0) bytesRemaining -= result;
		return result;
	}
	}

	private final class ChunkedInputStream extends InputStream {
		int bytesRemaining = -1;
		boolean atEnd = false;
	/**
	 * @throws 		IOException
	 */
	public ChunkedInputStream() throws IOException {
		readChunkSize();
	}
	/**
	 * @see 		java.io.InputStream#close()
	 */
	public void close() throws IOException {
		atEnd = true;
		closeSocket();
	}
	/**
	 * @see 		java.io.InputStream#available()
	 */
	public int available() throws IOException {
		int result = is.available();
		if (result > bytesRemaining) return bytesRemaining;
		return result;
	}
	private void readChunkSize() throws IOException {
		if (atEnd) return;
		if (bytesRemaining == 0) readln(); // read CR/LF
		String size = readln();
		int index = size.indexOf(";"); //$NON-NLS-1$
		if (index >= 0) size = size.substring(0, index);
		bytesRemaining = Integer.parseInt(size.trim(), 16);
		if (bytesRemaining == 0) {
			atEnd = true;
			readHeaders(resHeader);
		}
	}
	/**
	 * @see 		java.io.InputStream#read()
	 */
	public int read() throws IOException {
		if (bytesRemaining <= 0) readChunkSize();
		if (atEnd) return -1;
		bytesRemaining--;
		return is.read();
	}
	/**
	 * @see 		java.io.InputStream#read(byte[], int, int)
	 */
	public int read(byte[] buf, int offset, int length) throws IOException {
		if (buf == null) throw new NullPointerException();
		// avoid int overflow
		if (offset < 0 || length < 0 || offset > buf.length || buf.length - offset < length)
			throw new ArrayIndexOutOfBoundsException();
		if (bytesRemaining <= 0) readChunkSize();
		if (atEnd) return -1;
		if (length > bytesRemaining) length = bytesRemaining;
		int result = is.read(buf, offset, length);
		if (result > 0) bytesRemaining -= result;
		return result;
	}
	/**
	 * @param 		amount
	 * @return		the result
	 *
	 * @throws 		IOException
	 */
	public long skip(long amount) throws IOException {
		if (atEnd) return -1;
		if (bytesRemaining <= 0) readChunkSize();
		if (amount > bytesRemaining) amount = bytesRemaining;
		long result = is.skip(amount);
		if (result > 0) bytesRemaining -= result;
		return result;
	}
	}

	private final class HttpOutputStream extends OutputStream {
		static final int MAX = 1024;
		ByteArrayOutputStream cache = new ByteArrayOutputStream(MAX+7);
		boolean chunked, closed = false;

	/**
	 * @param 		chunked
	 */
	public HttpOutputStream(boolean chunked) {
		this.chunked = chunked;
	}
	private void output(String output) throws IOException {
		socketOut.write(output.getBytes("ISO8859_1"));
	}
	synchronized void sendCache(boolean close) throws IOException {
		if (cache == null) return;
		int size = cache.size();
		if (size > 0 || close) {
			if (size > 0) {
				output(Integer.toHexString(size) + "\r\n");
				cache.write('\r'); cache.write('\n');
			}
			if (close) {
				cache.write('0');
				cache.write('\r'); cache.write('\n');
				cache.write('\r'); cache.write('\n');
			}
			socketOut.write(cache.toByteArray());
			if (close) {
				socketOut.flush();
				chunked = false;
				cache = null;
			} else cache.reset();
		}
	}
	/**
	 * @see 		java.io.OutputStream#flush()
	 */
	public synchronized void flush() throws IOException {
		if (closed) throw new IOException(com.ibm.oti.util.Msg.getString("K0059"));

		if (!sentRequest) {
			// Must set before calling sendRequest(), or it will send the cached data
			chunked = true;
			sendRequest();
		}
		sendCache(false);
		socketOut.flush();
	}
	/**
	 * @see 		java.io.OutputStream#close()
	 */
	public synchronized void close() throws IOException {
		if (closed) return;
		closed = true;
		IOException ex = null;
		try {
			if (chunked) {
				if (sentRequest && socketOut != null)
					sendCache(closed);
			} else if (!sentRequest) sendRequest();
		} catch (IOException e) {
			// If an exception occurred sending the data, close the socket if
			// required and then throw the exception
			ex = e;
		}
		if (conClosed) {
			if (socketOut != null)
				socketOut.close();
			if (socket != null)
				socket.close();
		}
		if (ex != null) throw ex;
	}
	/**
	 * @see 		java.io.OutputStream#write(int)
	 */
	public synchronized void write(int data) throws IOException {
		if (closed) throw new IOException(com.ibm.oti.util.Msg.getString("K0059"));
		if (cache != null) {
			cache.write(data);
			if (chunked && cache.size() >= MAX)
				sendCache(false);
		}
	}
	/**
	 * @see 		java.io.OutputStream#write(byte[], int, int)
	 */
	public synchronized void write(byte[] buffer, int offset, int count) throws IOException {
		if (closed) throw new IOException(com.ibm.oti.util.Msg.getString("K0059"));
		if (buffer==null) throw new NullPointerException();
		// avoid int overflow
		if (offset < 0 || count < 0 || offset > buffer.length || buffer.length - offset < count)
			throw new ArrayIndexOutOfBoundsException(com.ibm.oti.util.Msg.getString("K002f"));

		if (!chunked || cache.size() + count < MAX) {
			if (cache != null)
				cache.write(buffer, offset, count);
		} else {
			if (chunked) {
				if (!sentRequest) sendRequest();
				output(Integer.toHexString(count + cache.size()) + "\r\n");
			}
			socketOut.write(cache.toByteArray());
			cache.reset();
			socketOut.write(buffer, offset, count);
			if (chunked) output("\r\n");
		}
	}
	synchronized int size() {
		return cache.size();
	}
	synchronized byte[] toByteArray() {
		byte[] result = cache.toByteArray();
		cache = null;
		return result;
	}
	boolean isCached() {
		return !chunked;
	}
	boolean isChunked() {
		return chunked;
	}
	};

/**
 *
 */
public HttpConnectionPatched() {
}

/**
 * @see javax.microedition.io.Connection#close()
 */
public void close() throws IOException {
	conClosed = true;
	if (inputStatus != OPEN && (os == null || os.closed)) {
		// closing the input stream closes the socket, so we don't
		// need to close if the input stream has been opened
		if (os != null)
			os.close();
		if (uis != null)
			uis.close();
		closeSocket();
	}
}

void closeConnection() throws IOException {
	conClosed = true;
	closeSocket();
}

void closeSocket() throws IOException {
	if (is != null) {
		is.close();
	}
	if (socketOut != null)
		socketOut.close();
	if (socket != null)
		socket.close();
}

/**
 * Answers the date in milliseconds since epoch when this response header was created,
 * or 0 if the field <code>Date</code> is not found in the header.
 *
 * @return 		Date in millisecond since epoch
 *
 * @throws		IOException		if an IO error occurs while getting the creation date
 *
 * @see			#getExpiration()
 * @see			#getLastModified()
 * @see			java.util.Date
 *
 */
public long getDate() throws IOException {
	return getHeaderFieldDate("Date", 0);
}

/**
 * Answers the date in milliseconds since epoch when this response header expires
 * or 0 if the field <code>Expires</code> is not found in the header.
 *
 * @return 		Date in milliseconds since epoch
 *
 * @throws		IOException		if an IO error occurs while getting the expiration date
 *
 * @see 		#getHeaderFieldDate
 */
public long getExpiration() throws IOException {
	return getHeaderFieldDate("Expires", 0);
}

/**
 * Answers the file component of this URL.
 *
 * @return		the receiver's file.
 */
public String getFile() {
	if (file == null) return null;
	int index = file.indexOf('?');
	if (index != -1)
		return file.substring(0, index);
	index = file.indexOf('#');
	if (index == -1) return file;
	return file.substring(0, index);
}

/**
 * Answers the value of the field at position <code>pos<code>.
 * Answers <code>null</code> if there is fewer than <code>pos</code> fields
 * in the response header.
 *
 * @author		OTI
 * @version		initial
 *
 * @param 		pos 		the position of the field from the top
 * @return 		the value of the field
 *
 * @throws		IOException		if an IO error occurs while getting the field
 *
 * @see 		#getHeaderFieldDate
 * @see 		#getHeaderFieldInt
 * @see 		#getHeaderFieldKey
 */
public String getHeaderField(int pos) throws IOException {
	if (conClosed) throw new IOException(com.ibm.oti.util.Msg.getString("K00ac"));
	doRequest();
	return resHeader.get(pos + 1);
}

/**
 * Answers the value of the field corresponding to the <code>key</code>
 * Answers <code>null</code> if there is no such field.
 *
 * @param 		key			the name of the header field
 * @return 		the value of the header field
 *
 * @throws		IOException		if an IO error occurs while getting the field
 *
 * @see 		#getHeaderFieldDate
 * @see 		#getHeaderFieldInt
 * @see 		#getHeaderFieldKey
 */
public String getHeaderField(String key) throws IOException {
	if (conClosed) throw new IOException(com.ibm.oti.util.Msg.getString("K00ac"));
	doRequest();
	if (key == null) return null;
	return resHeader.get(key);
}

/**
 * Answers the date value in the form of milliseconds since epoch corresponding to the field <code>field</code>.
 * Answers <code>defaultValue</code> if no such field can be found in the response header.
 *
 * @param 		field 			the field in question
 * @param 		defaultValue 	the default value if no field is found
 * @return 		milliseconds since epoch
 *
 * @throws		IOException		if an IO error occurs while getting the field's date
 */
public long getHeaderFieldDate(String field, long defaultValue) throws IOException {
	String date = getHeaderField(field);
	if (date == null) return defaultValue;
	return Util.parseDate(date);
}

/**
 * Answers the integer value of the specified field.
 * Answers default value <code>defaultValue</code> if
 * no such field exists.
 *
 * @param 		field 			the field to return
 * @param 		defaultValue 	to be returned if <code>field></code> does not exist
 * @return 		Integer value of the field
 *
 * @throws		IOException		if an IO error occurs while getting the field's integer value
 */
public int getHeaderFieldInt(String field, int defaultValue) throws IOException {
	try {
		return Integer.parseInt(getHeaderField(field));
	} catch (NumberFormatException e) {
		return defaultValue;
	}
}

/**
 * Answers the name of the field at position specified by <code>pos</code>,
 * null if there are fewer than <code>posn</code> fields.
 *
 * @param 		pos		the position to look for; the first field being 0
 * @return 		the name of the field
 *
 * @throws		IOException		if an IO error occurs while getting the field key
 *
 * @see 		#getHeaderFieldDate
 * @see 		#getHeaderFieldInt
 * @see 		#getHeaderField(int)
 */
public String getHeaderFieldKey(int pos) throws IOException {
	if (conClosed) throw new IOException(com.ibm.oti.util.Msg.getString("K00ac"));
	doRequest();
	return resHeader.getKey(pos + 1);
}

/**
 * Answers the host component of this URL.
 *
 * @return		the receiver's host.
 */
public String getHost() {
	return host;
}

/**
 * Answers the value of the field <code>Last-Modified</code> in the response header,
 * 		 	0 if no such field exists
 *
 * @return		the value of <code>Last-Modified</code>
 *
 * @throws		IOException		if an IO error occurs while getting the value
 *
 * @see 		java.util.Date
 * @see 		#getDate()
 * @see 		#getExpiration()
 */
public long getLastModified() throws IOException {
	return getHeaderFieldDate("Last-Modified", 0);
}

/**
 * Answers the port component of this connection.
 *
 * @return		the receiver's port.
 */
public int getPort() {
	return port;
}

/**
 * Answers the protocol component of this connection.
 *
 * @return		the receiver's protocol.
 */
public String getProtocol() {
	return "http";
}

/**
 * Answers the query component of this connection.
 *
 * @return		the receiver's query.
 */
public String getQuery() {
	if (file == null) return null;
	int index = file.indexOf('?');
	if (index == -1) return null;
	String query = file.substring(index + 1);
	index = query.indexOf('#');
	if (index == -1) return query;
	return query.substring(0, index);
}

/**
 * Answers the ref component of this connection.
 *
 * @return		the receiver's ref.
 */
public String getRef() {
	if (file == null) return null;
	int index = file.indexOf('#');
	if (index == -1) return null;
	return file.substring(index + 1);
}

/**
 * Answers the request method which will be used to make the request to the remote HTTP server.
 * All possible methods of this HTTP impl is listed in the class definition.
 *
 * @return 		the request method string
 *
 * @see 		#method
 * @see			#setRequestMethod
 */
public String getRequestMethod() {
	return method;
}

/**
 * Answers the value corresponds to the field in the request Header, null if no such field exists
 *
 * @param		field		the field name
 * @return 		the field to look up
 *
 * @see 		#setRequestProperty
 */
public String getRequestProperty(String field) {
	return reqHeader.get(field);
}

/**
 * Answers the reponse code returned by the remote HTTP server
 *
 * @return 		the response code, -1 if no valid response code
 *
 * @throws 		IOException 	thrown when there is a IO error during the retrieval.
 *
 * @see #getResponseMessage()
 */
public int getResponseCode() throws IOException {
	if (conClosed) throw new IOException(com.ibm.oti.util.Msg.getString("K00ac"));

	// Response Code Sample : "HTTP/1.0 200 OK"

	// Call connect() first since getHeaderField() doesn't return exceptions
	doRequest();
	if (responseCode != -1) return responseCode;
	String response = resHeader.get(0);
	if (response == null || !response.startsWith("HTTP/"))
		return -1;
	response.trim();
	int mark = response.indexOf(" ") + 1;
	if (mark == 0) return -1;
	if (response.charAt(mark - 2) != '1')
		httpVersion = 0;
	int last = mark + 3;
	if (last > response.length()) last = response.length();
	responseCode = Integer.parseInt(response.substring(mark, last));
	if (last + 1 <= response.length())
		responseMessage = response.substring(last + 1);
	return responseCode;
}

/**
 * Answers the response message returned the remote HTTP server
 *
 * @return 		the response message. <code>null</code> if such response exists
 *
 * @throws		IOException		if an IO error occurs while getting the response message
 *
 * @see 		#getResponseCode()
 * @see 		java.io.IOException
 */
public String getResponseMessage() throws IOException {
	if (conClosed) throw new IOException(com.ibm.oti.util.Msg.getString("K00ac"));
	if (responseMessage != null) return responseMessage;
	getResponseCode();
	return responseMessage;
}

/**
 * Answers the URL for this connection.
 *
 * @return		the receiver's URL.
 */
public String getURL() {
	StringBuffer url = new StringBuffer(getProtocol());
	url.append(':');
	if (host != null) {
		url.append("//");
		url.append(host);
	}
	if (port != getDefaultPort()) {
		url.append(':');
		url.append(port);
	}
	if (file != null)
		url.append(file);
	return url.toString();
}

/**
 * Sets the request command which will be sent to the remote HTTP server.
 * This method can only be called before the connection is made.
 *
 * @param 		method		The <code>non-null</code> string representing the method
 *
 * @throws 		IOException 	if this is called after connected, or the method is not supported by this HTTP impl.
 *
 * @see 		#getRequestMethod
 * @see 		#method
 */
public void setRequestMethod(String method) throws IOException {
	if (sentRequest) throw new IOException(com.ibm.oti.util.Msg.getString("K0037"));
	// ignore if an output stream has already been opened to write POST data
	if (os != null) return;
	if (!method.equals(GET) && !method.equals(HEAD) && !method.equals(POST))
		throw new IOException(com.ibm.oti.util.Msg.getString("K00ad"));
	this.method = method;
}

/**
 * Sets the value of the request header field <code> field </code> to <code>newValue</code>
 * Only the current URL Connection is affected. It can only be called before the connection is made
 * This method must be overridden by protocols  which support the value of the fields.
 *
 * @param 		field		the name of field to be set
 * @param 		newValue	the new value for this field
 *
 * @throws		IOException		if an IO error occurs while setting the request property
 *
 * @see 		#getRequestProperty
 */
public void setRequestProperty(String field, String newValue) throws IOException {
	if (sentRequest) throw new IOException(com.ibm.oti.util.Msg.getString("K0037"));
	// ignore if an output stream has already been opened to write POST data
	if (os != null) return;
	reqHeader.add(field, newValue);
}

/**
 * Sets the socket parameters used to create the underlying socket.
 *
 * @param 		params 		one or more parameters of the form ;key=value
 *
 */
public void setSocketParameters(String params) {
	if (!params.startsWith(";"))
		throw new IllegalArgumentException();
	socketOptions = params;
}

/**
 * Sets the connection parameters.
 *
 * @param 		params 		one or more parameters of the form ;key=value
 *
 */
public void setConnectionParameters(String params) {
	String[][] equates = ConnectionUtil.getParameters(params);
	int[] result = new int[1];
	for (int i=0; i<equates.length; i++) {
		String key = equates[i][0];
		equates[i][0] = equates[i][0].toLowerCase();
		if (equates[i][0].equals("proxy") && equates[i][1] != null) {
			setProxy(equates[i][1]);
		} else if (ConnectionUtil.intParam("httpversion", equates[i], ConnectionUtil.NEGATIVE, result)) {
			if (result[0] > 1)
				throw new IllegalArgumentException(com.ibm.oti.util.Msg.getString("K009f", key, equates[i][1]));
			httpVersion = result[0];
		} else if (equates[i][0].equals("followredirects") && equates[i][1] != null) {
			String value = equates[i][1].toLowerCase();
			if (value.equals("false")) followRedirects = false;
			else if (!value.equals("true"))
				throw new IllegalArgumentException(com.ibm.oti.util.Msg.getString("K00b5", equates[i][1]));
		} else if (equates[i][0].equals("chunked") && equates[i][1] != null) {
			String value = equates[i][1].toLowerCase();
			if (value.equals("true")) sendChunked = true;
			else if (!value.equals("false"))
				throw new IllegalArgumentException(com.ibm.oti.util.Msg.getString("K00b5", equates[i][1]));
		} else throw new IllegalArgumentException(com.ibm.oti.util.Msg.getString("K00a5", key));
	}
}

/**
 * Passes the parameters from the Connector.open() method to this
 * object. Protocol used by MIDP 2.0
 *
 * @param		spec  		The address passed to Connector.open()
 * @param		access 		The type of access this Connection is granted (READ, WRITE, READ_WRITE)
 * @param		timeout 	A boolean indicating whether or not the caller to Connector.open() wants timeout exceptions
 * @return		the MIDP 2.0 connection
 *
 * @throws		IOException 	If an error occured opening and configuring serial port.
 *
 * @see javax.microedition.io.Connector
 */
public javax.microedition.io.Connection setParameters2(String spec, int access, boolean timeout) throws IOException {
	setParameters(spec, access, timeout);
	return this;
}

/**
 * Passes the parameters from the Connector.open() method to this
 * object. Protocol used by MIDP 1.0
 *
 * @param		spec 			The address passed to Connector.open()
 * @param		access 			The type of access this Connection is granted (READ, WRITE, READ_WRITE)
 * @param		throwTimeout  	A boolean indicating whether or not the caller to Connector.open() wants timeout exceptions
 *
 * @throws		IOException 	If an error occured opening and configuring serial port.
 *
 * @see 		javax.microedition.io.Connector
 */
public void setParameters(String spec, int access, boolean throwTimeout) throws IOException {
	String[][] equates = ConnectionUtil.NO_PARAMETERS;
	int index = spec.indexOf(';');
	if (index != -1) {
		equates = ConnectionUtil.getParameters(spec.substring(index + 1));
		StringBuffer url = new StringBuffer(spec.substring(0, index));
		for (int i=0; i<equates.length; i++) {
			if (equates[i][0].equals("j9proxy")) {
				setProxy(equates[i][1]);
			} else if (equates[i][0].equals("nokia_timeout")) {
				nokiaTimeout = Integer.parseInt(equates[i][1]);
			} else if (equates[i][0].equals("nokia_netid")) {
				apn += ";nokia_netid=" + Integer.parseInt(equates[i][1]);
			} else if (equates[i][0].equals("nokia_apnid")) {
				apn += ";nokia_apnid=" + Integer.parseInt(equates[i][1]);
			} else if (equates[i][0].equals("nokia_socketimpl")) {
				j9socket = false;
			} else {
				url.append(';');
				url.append(equates[i][0]);
				if (equates[i][1] != null) {
					url.append('=');
					url.append(equates[i][1]);
				}
			}
		}
		spec = url.toString();
	}

	this.access = access;
	timeout = throwTimeout;
	parseURL(spec);
	if (host == null)
		throw new IllegalArgumentException(com.ibm.oti.util.Msg.getString("K01cd", host));

	String proxyHost = System.getProperty("http.proxyHost");
	String portString = System.getProperty("http.proxyPort");
	if (proxyHost != null) {
		proxyName = proxyHost;
		if (portString != null)
			proxyPort = Integer.parseInt(portString);
		else proxyPort = 80;
	}
}

private void setProxy(String proxy) {
	int index = proxy.indexOf(':');
	if (index == -1) {
		proxyName = proxy;
		proxyPort = 80;
	} else {
		proxyName = proxy.substring(0, index);
		String port = proxy.substring(index + 1);
		try {
			proxyPort = Integer.parseInt(port);
		} catch (NumberFormatException e) {
			throw new IllegalArgumentException(com.ibm.oti.util.Msg.getString("K00af", port));
		}
		if (proxyPort < 0 || proxyPort > 65535)
			throw new IllegalArgumentException(com.ibm.oti.util.Msg.getString("K00b0"));
	}
}

/**
 * Get the default port number to be used if the port is
 * not specified.
 *
 * @return 		the default port number
 */
protected int getDefaultPort() {
	return 80;
}

private void parseURL(String url) {
	String hostPart = null;
	if (!url.startsWith("//")) {
		file = url;
		return;
	}
	url = url.substring(2);
	int index = url.indexOf('/');
	if (index == -1) {
		hostPart = url;
	} else {
		hostPart = url.substring(0, index);
		file = url.substring(index);
	}
	if ((index = hostPart.indexOf(':')) != -1) {
		host = hostPart.substring(0, index);
		String portString = hostPart.substring(index + 1);
		try {
			port = Integer.parseInt(portString);
		} catch (NumberFormatException e) {
			throw new IllegalArgumentException(com.ibm.oti.util.Msg.getString("K00b1"));
		}
		if (port < 0 || port > 65535)
			throw new IllegalArgumentException(com.ibm.oti.util.Msg.getString("K0325", port));
	} else {
		if (hostPart.length() > 0) host = hostPart;
		port = getDefaultPort();
	}
}

/**
 * Handles an HTTP request along with its redirects and authentication
 *
 * @throws		IOException		when an IO error occures while making a request
 */
void doRequest() throws IOException {
	if (sentRequest) {
		// If necessary, finish the request by
		// closing the uncached output stream.
		if (resHeader == null && os != null) {
			os.sendCache(true);
			readServerResponse();
			getContentStream();
		}
		return;
	}

	int redirect = 0;
	try {
		while(true) {
			// send the request and process the results
			sendRequest();
			if (os != null && os.isChunked())
				os.sendCache(true);
			readServerResponse();

			// See if there is a server redirect to the URL, but only handle 4 levels of
			// URL redirection from the server to avoid being caught in an infinite loop
			if (followRedirects) {
				if ((responseCode == HTTP_MULT_CHOICE || responseCode == HTTP_MOVED_PERM ||
				responseCode == HTTP_MOVED_TEMP || responseCode == HTTP_SEE_OTHER ||
				responseCode == HTTP_USE_PROXY) && os == null) {
					if (++redirect > 4)
						throw new IOException(com.ibm.oti.util.Msg.getString("K0093"));
					String location = resHeader.get("Location");
					if (location != null) {
						//start over
						if(location.startsWith(getProtocol() + ':')) {
							int start = getProtocol().length() + 1;
							if (responseCode == HTTP_USE_PROXY) {
								if(location.startsWith("//", start))
									setProxy(location.substring(start + 2));
								else
									setProxy(location.substring(start));
							}
							else
								parseURL(location.substring(start));
						}
						else {
							if (responseCode == HTTP_USE_PROXY) {
								if(location.startsWith("//"))
									setProxy(location.substring(2));
								else
									setProxy(location);
							}
							else
								parseURL(location);
						}

						closeSocket();
						connected = false;
						continue;
					}
				}
			}
			break;
		}
		// Cache the content stream and read the first chunked header
		getContentStream();
	} catch (RuntimeException e) {
		try {closeSocket();} catch (Exception i) {}
		throw e;
	} catch (IOException e) {
		try {closeSocket();} catch (Exception i) {}
		throw e;
	}

}

void readHeaders(Header headers) throws IOException {
	// parse the result headers until the first blank line
	String line;
	while (((line = readln())!=null) && (line.length() > 1)) {
		// Header parsing
		int idx;
		if ((idx = line.indexOf(":")) < 0)
			headers.add(null, line.trim());
		else
			headers.add(line.substring(0, idx), line.substring(idx + 1).trim());
	}
}

private byte[] createRequest() throws IOException {
	StringBuffer output = new StringBuffer(256);
	output.append(method);
	output.append(' ');
	output.append(requestString());
	output.append(' ');
	output.append("HTTP/1.");
	if (httpVersion == 0) output.append("0\r\n");
	else output.append("1\r\n");
	if (reqHeader.get("User-Agent") == null) {
		String agent = System.getProperty("http.agent");
		if (agent != null) {
			output.append("User-Agent: ");
			output.append(agent);
			output.append("\r\n");
		}
	}
	if (reqHeader.get("Host") == null) {
		output.append("Host: ");
		output.append(getHost());
		int port = getPort();
		if (port != 80) {
			output.append(':');
			output.append(Integer.toString(port));
		}
		output.append("\r\n");
	}
	if (httpVersion > 0 && reqHeader.get("Connection") == null)
		output.append("Connection: close\r\n");

	// if we are doing output make sure the appropriate headers are sent
	if (os != null) {
		if (reqHeader.get("Content-Type") == null)
			output.append("Content-Type: application/x-www-form-urlencoded\r\n");
		if (os.isCached()) {
			output.append("Content-Length: ");
			output.append(Integer.toString(os.size()));
			output.append("\r\n");
		} else if (os.isChunked())
			output.append("Transfer-Encoding: chunked\r\n");
	}

	// then the user-specified request headers, if any
	for (int i = 0; i < reqHeader.length(); i++) {
		String key = reqHeader.getKey(i);
		if (key != null) {
			String lKey = key.toLowerCase();
			if (!lKey.equals("content-length") &&
				((os != null && !os.isChunked()) || !lKey.equals("transfer-encoding")))
			{
				output.append(key);
				output.append(": ");
				output.append(reqHeader.get(i));
				output.append("\r\n");
			}
		}
	}
	// end the headers
	output.append("\r\n");
	return output.toString().getBytes("ISO8859_1");
}

/**
 * Sends the request header to the remote HTTP server
 * Not all of them are guaranteed to have any effect on the content the
 * server will return, depending on if the server supports that field.
 * <p>
 * Examples :	Accept: text/*, text/html, text/html;level=1,
 * 				Accept-Charset: iso-8859-5, unicode-1-1;q=0.8
 */
void sendRequest() throws IOException {
	byte[] request = createRequest();

	connect();
	byte[] outbuf = null;
	if (os != null && os.isCached())
		outbuf = os.toByteArray();
	// send out the HTTP request
	socketOut.write(request);
	// send any output to the socket (i.e. POST data)
	if (outbuf != null)
		socketOut.write(outbuf);
	if (os == null || outbuf != null)
		socketOut.flush();
	sentRequest = true;
}

void readServerResponse() throws IOException {
	is = new BufferedInputStream(socket.openInputStream());
	do {
		responseCode = -1;
		responseMessage = null;
		resHeader = new Header(true);

		String line = readln();
		// Add the response, it may contain ':' which we ignore
		if (line != null) {
			resHeader.add(null, line.trim());
			readHeaders(resHeader);
		}
	} while (getResponseCode() == 100);
}

/**
 * Answers a line read from the input stream. Does not include the
 * terminating CR-LF.
 *
 * @return 		the line read from the input stream
 */
String readln() throws IOException {
	boolean lastCr = false;
	StringBuffer result = new StringBuffer(80);
	int c = is.read();
	if (c < 0) return null;
	while (c != '\n') {
		if (lastCr) {
			result.append('\r');
			lastCr = false;
		}
		if (c == '\r') lastCr = true;
		else result.append((char)c);
		c = is.read();
		if (c < 0) break;
	}
	return result.toString();
}

protected void connect() throws IOException {
	if (connected) return;
	// if the request wasn't already sent, then send it
	socket = openSocket(timeout, socketOptions);
	connected = true;
	socketOut = socket.openOutputStream();
}

protected StreamConnection openSocket(boolean timeout, String socketOptions) throws IOException {
	openNetworkInterfaceAndUpdateProxyInformation();
	String spec = "//" + getHostName() + ":" + getHostPort() + socketOptions;
	if(!j9socket) {
		SocketConnection connection = (SocketConnection) new com.nokia.mj.impl.gcf.protocol.socket.Connection()
				.setParameters2(spec + apn, 3, timeout);
		return connection;
	}
	if (nokiaTimeout != -1) {
		spec += ";so_timeout=" + (nokiaTimeout * 1000);
	}
	StreamConnection connection;
	connection = new com.ibm.oti.connection.socket.Connection(0);
	((CreateConnection)connection).setParameters2(spec, Connector.READ_WRITE, timeout);
	return connection;
}

/**
 * Platform specific. Called before opening a Socket for a Http connection.
 * If necessary, open the network connection and set the http proxy settings.
 */
protected void openNetworkInterfaceAndUpdateProxyInformation() {
	String httpProxyHost = System.getProperty("http.proxyHost");
	String httpProxyPort = System.getProperty("http.proxyPort");

	if (httpProxyHost == null || httpProxyPort == null) {
		// call native to start network interface and get the
		// proxy values based on the specific IAP that gets started
		final String [] proxyValues = com.ibm.oti.vm.VM.getHttpProxyParms();
		if (proxyValues == null) {
			return;
		}

		// values[0] is hostname
		// values[1] is port number as String

		// Set the Local object instance variables
		proxyName = proxyValues[0];
		proxyPort = Integer.parseInt( proxyValues[1] );

		// Set the system properties
		com.ibm.oti.vm.VM.setSystemProperty("http.proxyHost", proxyName);
		com.ibm.oti.vm.VM.setSystemProperty("http.proxyPort", proxyValues[1]);
	}
}

/**
 * Creates an input stream for reading from this Connection.
 *
 * @return 		the input stream to read from
 * @throws 		IOException 	thrown when there is a IO error
 *
 * @see 		#openOutputStream()
 * @see 		java.io.InputStream
 * @see 		java.io.IOException
 */
public InputStream openInputStream() throws IOException {

	if (conClosed) throw new IOException(com.ibm.oti.util.Msg.getString("K00ac"));
	if (inputStatus != UNOPENED) throw new IOException(com.ibm.oti.util.Msg.getString("K0192"));

	doRequest();
	inputStatus = OPEN;
	return new InputStream() {
		public int available() throws IOException {
			if (inputStatus == CLOSED)
				throw new IOException(com.ibm.oti.util.Msg.getString("K0059"));
			return uis.available();
		}
		public int read() throws IOException {
			if (inputStatus == CLOSED)
				throw new IOException(com.ibm.oti.util.Msg.getString("K0059"));
			return uis.read();
		}
		public int read(byte[] buf, int offset, int length) throws IOException {
			if (inputStatus == CLOSED)
				throw new IOException(com.ibm.oti.util.Msg.getString("K0059"));
			return uis.read(buf, offset, length);
		}
		public long skip(long amount) throws IOException {
			if (inputStatus == CLOSED)
				throw new IOException(com.ibm.oti.util.Msg.getString("K0059"));
			return uis.skip(amount);
		}
		public void close() throws IOException {
			if (inputStatus != CLOSED) {
				inputStatus = CLOSED;
				closeSocket();
			}
		}
	};
}

private InputStream getContentStream() throws IOException {

	String encoding = resHeader.get("Transfer-Encoding");
	if (encoding != null && encoding.toLowerCase().equals("chunked"))
		return uis = new ChunkedInputStream();

	String sLength = resHeader.get("Content-Length");
	if (sLength != null) {
		try {
			int length = Integer.parseInt(sLength);
			return uis = new LimitedInputStream(length);
		} catch (NumberFormatException e) {}
	}
	return uis = is;
}

/**
 * Creates an output stream for writing to this Connection.
 *
 * @return 		the output stream to write to
 * @throws 		IOException 	thrown when there is a IO error
 *
 * @see 		#openInputStream()
 * @see 		java.io.IOException
 */
public OutputStream openOutputStream() throws IOException {
	if (conClosed) throw new IOException(com.ibm.oti.util.Msg.getString("K00ac"));

	if (access != Connector.WRITE && access != Connector.READ_WRITE)
		throw new IOException(com.ibm.oti.util.Msg.getString("K00aa"));
	// you can't write after you read
	if (sentRequest && os == null)
		throw new IOException(com.ibm.oti.util.Msg.getString("K0037"));

	if (outputStatus != UNOPENED) throw new IOException(com.ibm.oti.util.Msg.getString("K0192"));

	if (os == null) {

		String encoding = reqHeader.get("Transfer-Encoding");
		if (encoding != null) encoding = encoding.toLowerCase();
		os = new HttpOutputStream(sendChunked || "chunked".equals(encoding));
	}

	outputStatus = OPEN;

	return new OutputStream() {
		public void write(int value) throws IOException {
			if (outputStatus == CLOSED)
				throw new IOException(com.ibm.oti.util.Msg.getString("K0059"));
			os.write(value);
		}
		public void write(byte[] buf, int offset, int length) throws IOException {
			if (outputStatus == CLOSED)
				throw new IOException(com.ibm.oti.util.Msg.getString("K0059"));
			os.write(buf, offset, length);
		}
		public void flush() throws IOException {
			if (outputStatus == CLOSED)
				throw new IOException(com.ibm.oti.util.Msg.getString("K0059"));
			os.flush();
		}
		public void close() throws IOException {
			if (outputStatus != CLOSED) {
				outputStatus = CLOSED;
				os.close();
			}
		}
	};
}

private String requestString() {
	if (proxyName != null) return getURL();
	return file == null ? "/" : file;
}

/**
 * Get the hostname of the connection machine. This is either
 * the name given in the URL or the name of the proxy
 * server.
 *
 * @return		the host name
 */
protected String getHostName() {
	if (proxyName != null) return proxyName;
	return getHost();
}

/**
 * Get the connection port. This is either the URL's port or the
 * proxy port if a proxy port has been set.
 *
 * @return		the host port
 */
protected int getHostPort() {
	if (proxyName != null) return proxyPort;
	return getPort();
}

/**
 * Answers the content length of the response body, -1 if no such
 * field is found in the header response.
 *
 * @return 		the content length
 */
public long getLength() {
	try {
		String sLength = getHeaderField("Content-Length");
		if (sLength == null) return -1;
		return Long.parseLong(sLength);
	} catch (IOException e) {
		return -1;
	} catch (NumberFormatException e) {
		return -1;
	}
}

/**
 * Answers the content encoding of the response body, null if no such
 * field is found in the header response.
 *
 * @return 		the content encoding
 */
public String getEncoding() {
	try {
		return getHeaderField("Content-Encoding");
	} catch (IOException e) {
		return null;
	}
}

/**
 * Answers the content type of the response body, null if no such
 * field is found in the header response.
 *
 * @return 		the content type
 */
public String getType() {
	try {
		return getHeaderField("Content-Type");
	} catch (IOException e) {
		return null;
	}
}

/**
 * Answers whether the connection is closed.
 *
 * @return 		<code>true</code> if the connection is closed, <code>false</code> otherwise.
 */
protected boolean isClosed() {
	return conClosed;
}

}
