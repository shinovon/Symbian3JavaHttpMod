// Copyright IBM
// Decompiled by Jad v1.5.8g. Copyright 2001 Pavel Kouznetsov.
package com.nokia.mj.impl.gcf.protocol.http;

import com.ibm.oti.connection.BufferedInputStream;
import com.ibm.oti.connection.ConnectionUtil;
import com.ibm.oti.connection.CreateConnection;
import com.ibm.oti.connection.DataConnection;
import com.ibm.oti.connection.http.Header;
import com.ibm.oti.util.Msg;
import com.ibm.oti.util.Util;
import com.ibm.oti.vm.VM;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import javax.microedition.io.ContentConnection;
import javax.microedition.io.HttpConnection;
import javax.microedition.io.InputConnection;
import javax.microedition.io.OutputConnection;
import javax.microedition.io.SocketConnection;
import javax.microedition.io.StreamConnection;

public class HttpConnectionPatched extends DataConnection implements CreateConnection, ContentConnection, HttpConnection {
	private final class LimitedInputStream extends InputStream {

		int bytesRemaining;

		public void close() throws IOException {
			bytesRemaining = 0;
			closeSocket();
		}

		public int available() throws IOException {
			int result = is.available();
			if (result > bytesRemaining)
				return bytesRemaining;
			else
				return result;
		}

		public int read() throws IOException {
			if (bytesRemaining <= 0) {
				return -1;
			} else {
				int result = is.read();
				bytesRemaining--;
				return result;
			}
		}

		public int read(byte buf[], int offset, int length) throws IOException {
			if (buf == null)
				throw new NullPointerException();
			if (offset < 0 || length < 0 || offset > buf.length || buf.length - offset < length)
				throw new ArrayIndexOutOfBoundsException();
			if (bytesRemaining <= 0)
				return -1;
			if (length > bytesRemaining)
				length = bytesRemaining;
			int result = is.read(buf, offset, length);
			if (result > 0)
				bytesRemaining -= result;
			return result;
		}

		public long skip(long amount) throws IOException {
			if (bytesRemaining <= 0)
				return -1L;
			if (amount > bytesRemaining)
				amount = bytesRemaining;
			long result = is.skip(amount);
			if (result > 0L)
				bytesRemaining -= result;
			return result;
		}

		public LimitedInputStream(int length) {
			bytesRemaining = length;
		}
	}

	private final class ChunkedInputStream extends InputStream {

		int bytesRemaining;
		boolean atEnd;

		public void close() throws IOException {
			atEnd = true;
			closeSocket();
		}

		public int available() throws IOException {
			int result = is.available();
			if (result > bytesRemaining)
				return bytesRemaining;
			else
				return result;
		}

		private void readChunkSize() throws IOException {
			if (atEnd)
				return;
			if (bytesRemaining == 0)
				readln();
			String size = readln();
			int index = size.indexOf(";");
			if (index >= 0)
				size = size.substring(0, index);
			bytesRemaining = Integer.parseInt(size.trim(), 16);
			if (bytesRemaining == 0) {
				atEnd = true;
				readHeaders(resHeader);
			}
		}

		public int read() throws IOException {
			if (bytesRemaining <= 0)
				readChunkSize();
			if (atEnd) {
				return -1;
			} else {
				bytesRemaining--;
				return is.read();
			}
		}

		public int read(byte buf[], int offset, int length) throws IOException {
			if (buf == null)
				throw new NullPointerException();
			if (offset < 0 || length < 0 || offset > buf.length || buf.length - offset < length)
				throw new ArrayIndexOutOfBoundsException();
			if (bytesRemaining <= 0)
				readChunkSize();
			if (atEnd)
				return -1;
			if (length > bytesRemaining)
				length = bytesRemaining;
			int result = is.read(buf, offset, length);
			if (result > 0)
				bytesRemaining -= result;
			return result;
		}

		public long skip(long amount) throws IOException {
			if (atEnd)
				return -1L;
			if (bytesRemaining <= 0)
				readChunkSize();
			if (amount > bytesRemaining)
				amount = bytesRemaining;
			long result = is.skip(amount);
			if (result > 0L)
				bytesRemaining -= result;
			return result;
		}

		public ChunkedInputStream() throws IOException {
			bytesRemaining = -1;
			atEnd = false;
			readChunkSize();
		}
	}

	private final class HttpOutputStream extends OutputStream {

		static final int MAX = 1024;
		ByteArrayOutputStream cache;
		boolean chunked;
		boolean closed;

		private void output(String output) throws IOException {
			socketOut.write(output.getBytes("ISO8859_1"));
		}

		synchronized void sendCache(boolean close) throws IOException {
			if (cache == null)
				return;
			int size = cache.size();
			if (size > 0 || close) {
				if (size > 0) {
					output(Integer.toHexString(size) + "\r\n");
					cache.write(13);
					cache.write(10);
				}
				if (close) {
					cache.write(48);
					cache.write(13);
					cache.write(10);
					cache.write(13);
					cache.write(10);
				}
				socketOut.write(cache.toByteArray());
				if (close) {
					socketOut.flush();
					chunked = false;
					cache = null;
				} else {
					cache.reset();
				}
			}
		}

		public synchronized void flush() throws IOException {
			if (closed)
				throw new IOException(Msg.getString("K0059"));
			if (!sentRequest) {
				chunked = true;
				sendRequest();
			}
			sendCache(false);
			socketOut.flush();
		}

		public synchronized void close() throws IOException {
			if (closed)
				return;
			closed = true;
			IOException ex = null;
			try {
				if (chunked) {
					if (sentRequest && socketOut != null)
						sendCache(closed);
				} else if (!sentRequest)
					sendRequest();
			} catch (IOException e) {
				ex = e;
			}
			if (conClosed) {
				if (socketOut != null)
					socketOut.close();
				if (socket != null)
					socket.close();
			}
			if (ex != null)
				throw ex;
			else
				return;
		}

		public synchronized void write(int data) throws IOException {
			if (closed)
				throw new IOException(Msg.getString("K0059"));
			if (cache != null) {
				cache.write(data);
				if (chunked && cache.size() >= MAX)
					sendCache(false);
			}
		}

		public synchronized void write(byte buffer[], int offset, int count) throws IOException {
			if (closed)
				throw new IOException(Msg.getString("K0059"));
			if (buffer == null)
				throw new NullPointerException();
			if (offset < 0 || count < 0 || offset > buffer.length || buffer.length - offset < count)
				throw new ArrayIndexOutOfBoundsException(Msg.getString("K002f"));
			if (!chunked || cache.size() + count < MAX) {
				if (cache != null)
					cache.write(buffer, offset, count);
			} else {
				if (chunked) {
					if (!sentRequest)
						sendRequest();
					output(Integer.toHexString(count + cache.size()) + "\r\n");
				}
				socketOut.write(cache.toByteArray());
				cache.reset();
				socketOut.write(buffer, offset, count);
				if (chunked)
					output("\r\n");
			}
		}

		synchronized int size() {
			return cache.size();
		}

		synchronized byte[] toByteArray() {
			byte result[] = cache.toByteArray();
			cache = null;
			return result;
		}

		boolean isCached() {
			return !chunked;
		}

		boolean isChunked() {
			return chunked;
		}

		public HttpOutputStream(boolean chunked) {
			cache = new ByteArrayOutputStream(1031);
			closed = false;
			this.chunked = chunked;
		}
	}

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
	private static final int UNOPENED = 0;
	private static final int OPEN = 1;
	private static final int CLOSED = 2;
	int access;
	String host;
	String file;
	int httpVersion;
	boolean sentRequest;
	boolean conClosed;
	String method;
	int responseCode;
	String responseMessage;
	Header reqHeader;
	Header resHeader;
	protected boolean timeout;
	InputStream is;
	InputStream uis;
	protected OutputStream socketOut;
	HttpOutputStream os;
	String proxyName;
	protected int port;
	int proxyPort;
	boolean followRedirects;
	boolean sendChunked;
	protected String socketOptions;
	protected StreamConnection socket;
	protected boolean connected;
	private int inputStatus;
	private int outputStatus;
	private int nokiaTimeout = -1;
	private boolean j9socket = true;
	private String apn = "";

	public HttpConnectionPatched() {
		httpVersion = 1;
		sentRequest = false;
		conClosed = false;
		method = "GET";
		responseCode = -1;
		reqHeader = new Header(false);
		//followRedirects = true;
		sendChunked = false;
		socketOptions = "";
		connected = false;
		inputStatus = 0;
		outputStatus = 0;
		return;
	}

	public void close() throws IOException {
		conClosed = true;
		if (inputStatus != 1 && (os == null || os.closed)) {
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
		if (is != null)
			is.close();
		if (socketOut != null)
			socketOut.close();
		if (socket != null)
			socket.close();
	}

	public long getDate() throws IOException {
		return getHeaderFieldDate("Date", 0L);
	}

	public long getExpiration() throws IOException {
		return getHeaderFieldDate("Expires", 0L);
	}

	public String getFile() {
		if (file == null)
			return null;
		int index = file.indexOf('?');
		if (index != -1)
			return file.substring(0, index);
		index = file.indexOf('#');
		if (index == -1)
			return file;
		else
			return file.substring(0, index);
	}

	public String getHeaderField(int pos) throws IOException {
		if (conClosed) {
			throw new IOException(Msg.getString("K00ac"));
		} else {
			doRequest();
			return resHeader.get(pos + 1);
		}
	}

	public String getHeaderField(String key) throws IOException {
		if (conClosed)
			throw new IOException(Msg.getString("K00ac"));
		doRequest();
		if (key == null)
			return null;
		else
			return resHeader.get(key);
	}

	public long getHeaderFieldDate(String field, long defaultValue) throws IOException {
		String date = getHeaderField(field);
		if (date == null)
			return defaultValue;
		else
			return Util.parseDate(date);
	}

	public int getHeaderFieldInt(String field, int defaultValue) throws IOException {
		try {
			return Integer.parseInt(getHeaderField(field));
		} catch (NumberFormatException _ex) {
			return defaultValue;
		}
	}

	public String getHeaderFieldKey(int pos) throws IOException {
		if (conClosed) {
			throw new IOException(Msg.getString("K00ac"));
		} else {
			doRequest();
			return resHeader.getKey(pos + 1);
		}
	}

	public String getHost() {
		return host;
	}

	public long getLastModified() throws IOException {
		return getHeaderFieldDate("Last-Modified", 0L);
	}

	public int getPort() {
		return port;
	}

	public String getProtocol() {
		return "http";
	}

	public String getQuery() {
		if (file == null)
			return null;
		int index = file.indexOf('?');
		if (index == -1)
			return null;
		String query = file.substring(index + 1);
		index = query.indexOf('#');
		if (index == -1)
			return query;
		else
			return query.substring(0, index);
	}

	public String getRef() {
		if (file == null)
			return null;
		int index = file.indexOf('#');
		if (index == -1)
			return null;
		else
			return file.substring(index + 1);
	}

	public String getRequestMethod() {
		return method;
	}

	public String getRequestProperty(String field) {
		return reqHeader.get(field);
	}

	public int getResponseCode() throws IOException {
		if (conClosed)
			throw new IOException(Msg.getString("K00ac"));
		doRequest();
		if (responseCode != -1)
			return responseCode;
		String response = resHeader.get(0);
		if (response == null || !response.startsWith("HTTP/"))
			return -1;
		response.trim();
		int mark = response.indexOf(" ") + 1;
		if (mark == 0)
			return -1;
		if (response.charAt(mark - 2) != '1')
			httpVersion = 0;
		int last = mark + 3;
		if (last > response.length())
			last = response.length();
		responseCode = Integer.parseInt(response.substring(mark, last));
		if (last + 1 <= response.length())
			responseMessage = response.substring(last + 1);
		return responseCode;
	}

	public String getResponseMessage() throws IOException {
		if (conClosed)
			throw new IOException(Msg.getString("K00ac"));
		if (responseMessage != null) {
			return responseMessage;
		} else {
			getResponseCode();
			return responseMessage;
		}
	}

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

	public void setRequestMethod(String method) throws IOException {
		if (sentRequest)
			throw new IOException(Msg.getString("K0037"));
		if (os != null)
			return;
		if (!method.equals("GET") && !method.equals("HEAD") && !method.equals("POST")) {
			throw new IOException(Msg.getString("K00ad"));
		} else {
			this.method = method;
			return;
		}
	}

	public void setRequestProperty(String field, String newValue) throws IOException {
		if (sentRequest)
			throw new IOException(Msg.getString("K0037"));
		if (os != null) {
			return;
		} else {
			reqHeader.add(field, newValue);
			return;
		}
	}

	public void setSocketParameters(String params) {
		if (!params.startsWith(";")) {
			throw new IllegalArgumentException();
		} else {
			socketOptions = params;
			return;
		}
	}

	public void setConnectionParameters(String params) {
		String equates[][] = ConnectionUtil.getParameters(params);
		int result[] = new int[1];
		for (int i = 0; i < equates.length; i++) {
			String key = equates[i][0];
			equates[i][0] = equates[i][0].toLowerCase();
			if (equates[i][0].equals("proxy") && equates[i][1] != null)
				setProxy(equates[i][1]);
			else if (ConnectionUtil.intParam("httpversion", equates[i], 1, result)) {
				if (result[0] > 1)
					throw new IllegalArgumentException(Msg.getString("K009f", key, equates[i][1]));
				httpVersion = result[0];
			} else if (equates[i][0].equals("followredirects") && equates[i][1] != null) {
				String value = equates[i][1].toLowerCase();
				if (value.equals("false"))
					followRedirects = false;
				else if (!value.equals("true"))
					throw new IllegalArgumentException(Msg.getString("K00b5", equates[i][1]));
			} else if (equates[i][0].equals("chunked") && equates[i][1] != null) {
				String value = equates[i][1].toLowerCase();
				if (value.equals("true"))
					sendChunked = true;
				else if (!value.equals("false"))
					throw new IllegalArgumentException(Msg.getString("K00b5", equates[i][1]));
			} else {
				throw new IllegalArgumentException(Msg.getString("K00a5", key));
			}
		}

	}

	public javax.microedition.io.Connection setParameters2(String spec, int access, boolean throwTimeout)
			throws IOException {
		String equates[][] = ConnectionUtil.NO_PARAMETERS;
		int index = spec.indexOf(';');
		if (index != -1) {
			equates = ConnectionUtil.getParameters(spec.substring(index + 1));
			StringBuffer url = new StringBuffer(spec.substring(0, index));
			for (int i = 0; i < equates.length; i++)
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

			spec = url.toString();
		}
		this.access = access;
		timeout = throwTimeout;
		parseURL(spec);
		if (host == null)
			throw new IllegalArgumentException(Msg.getString("K01cd", host));
		String proxyHost = System.getProperty("http.proxyHost");
		String portString = System.getProperty("http.proxyPort");
		if (proxyHost != null) {
			proxyName = proxyHost;
			if (portString != null)
				proxyPort = Integer.parseInt(portString);
			else
				proxyPort = 80;
		}
		return this;
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
			} catch (NumberFormatException _ex) {
				throw new IllegalArgumentException(Msg.getString("K00af", port));
			}
			if (proxyPort < 0 || proxyPort > 65535)
				throw new IllegalArgumentException(Msg.getString("K00b0"));
		}
	}

	protected int getDefaultPort() {
		return 80;
	}

	private void parseURL(String url) {
		String hostPart = null;
		int index;
		if (!url.startsWith("//")) {
			if (url.startsWith("/")) {
				file = url;
			} else {
				index = -1;
				if (file != null)
					index = file.lastIndexOf('/');
				if (index == -1)
					file = "/" + url;
				else
					file = file.substring(0, index + 1) + url;
			}
			return;
		}
		url = url.substring(2);
		index = url.indexOf('/');
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
			} catch (NumberFormatException _ex) {
				throw new IllegalArgumentException(Msg.getString("K00b1"));
			}
			if (port < 0 || port > 65535)
				throw new IllegalArgumentException(Msg.getString("K0325", port));
		} else {
			if (hostPart.length() > 0)
				host = hostPart;
			port = getDefaultPort();
		}
	}

	void doRequest() throws IOException {
		if (sentRequest) {
			if (resHeader == null && os != null) {
				os.sendCache(true);
				readServerResponse();
				getContentStream();
			}
			return;
		}
		int redirect = 0;
		try {
			do {
				sendRequest();
				if (os != null && os.isChunked())
					os.sendCache(true);
				readServerResponse();
				if (!followRedirects || responseCode != 300 && responseCode != 301 && responseCode != 302
						&& responseCode != 303 && responseCode != 305 || os != null)
					break;
				if (++redirect > 4)
					throw new IOException(Msg.getString("K0093"));
				String location = resHeader.get("Location");
				if (location == null)
					break;
				if (location.startsWith(getProtocol() + ':')) {
					int start = getProtocol().length() + 1;
					if (responseCode == 305) {
						if (location.startsWith("//", start))
							setProxy(location.substring(start + 2));
						else
							setProxy(location.substring(start));
					} else {
						parseURL(location.substring(start));
					}
				} else if (responseCode == 305) {
					if (location.startsWith("//"))
						setProxy(location.substring(2));
					else
						setProxy(location);
				} else {
					parseURL(location);
				}
				closeSocket();
				connected = false;
			} while (true);
			getContentStream();
		} catch (RuntimeException e) {
			try {
				closeSocket();
			} catch (Exception _ex) {
			}
			throw e;
		} catch (IOException e) {
			try {
				closeSocket();
			} catch (Exception _ex) {
			}
			throw e;
		}
	}

	void readHeaders(Header headers) throws IOException {
		String line;
		int idx;
		while ((line = readln()) != null && line.length() > 1)
			if ((idx = line.indexOf(":")) < 0)
				headers.add(null, line.trim());
			else
				headers.add(line.substring(0, idx), line.substring(idx + 1).trim());
	}

	private byte[] createRequest() throws IOException {
		StringBuffer output = new StringBuffer(256);
		output.append(method);
		output.append(' ');
		output.append(requestString());
		output.append(' ');
		output.append("HTTP/1.");
		if (httpVersion == 0)
			output.append("0\r\n");
		else
			output.append("1\r\n");
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
		for (int i = 0; i < reqHeader.length(); i++) {
			String key = reqHeader.getKey(i);
			if (key != null) {
				String lKey = key.toLowerCase();
				if (!lKey.equals("content-length")
						&& (os != null && !os.isChunked() || !lKey.equals("transfer-encoding"))) {
					output.append(key);
					output.append(": ");
					output.append(reqHeader.get(i));
					output.append("\r\n");
				}
			}
		}

		output.append("\r\n");
		return output.toString().getBytes("ISO8859_1");
	}

	void sendRequest() throws IOException {
		byte request[] = createRequest();
		connect();
		byte outbuf[] = (byte[]) null;
		if (os != null && os.isCached())
			outbuf = os.toByteArray();
		socketOut.write(request);
		if (outbuf != null)
			socketOut.write(outbuf);
		if (os == null || outbuf != null)
			socketOut.flush();
		sentRequest = true;
	}

	void readServerResponse() throws IOException {
		is = new BufferedInputStream(socket.openInputStream());
		//is = socket.openInputStream();
		do {
			responseCode = -1;
			responseMessage = null;
			resHeader = new Header(true);
			String line = readln();
			if (line != null) {
				resHeader.add(null, line.trim());
				readHeaders(resHeader);
			}
		} while (getResponseCode() == 100);
	}

	String readln() throws IOException {
		boolean lastCr = false;
		StringBuffer result = new StringBuffer(80);
		int c = is.read();
		if (c < 0)
			return null;
		while (c != 10) {
			if (lastCr) {
				result.append('\r');
				lastCr = false;
			}
			if (c == 13)
				lastCr = true;
			else
				result.append((char) c);
			c = is.read();
			if (c < 0)
				break;
		}
		return result.toString();
	}

	protected void connect() throws IOException {
		if (connected) {
			return;
		} else {
			socket = openSocket(timeout, socketOptions);
			connected = true;
			socketOut = socket.openOutputStream();
			return;
		}
	}

	protected StreamConnection openSocket(boolean timeout, String socketOptions) throws IOException {
		openNetworkInterfaceAndUpdateProxyInformation();
		String spec = "//" + getHostName() + ":" + getHostPort() + socketOptions;
		if (j9socket) {
			if (nokiaTimeout != -1) {
				spec += ";so_timeout=" + (nokiaTimeout * 1000);
			}
			StreamConnection connection = new com.ibm.oti.connection.socket.Connection(0);
			return (StreamConnection) ((CreateConnection) connection).setParameters2(spec, 3, timeout);
		}
		SocketConnection connection = (SocketConnection) new com.nokia.mj.impl.gcf.protocol.socket.Connection()
				.setParameters2(spec + apn, 3, timeout);

		return connection;
	}

	protected void openNetworkInterfaceAndUpdateProxyInformation() {
		String httpProxyHost = System.getProperty("http.proxyHost");
		String httpProxyPort = System.getProperty("http.proxyPort");
		if (httpProxyHost == null || httpProxyPort == null) {
			String proxyValues[] = VM.getHttpProxyParms();
			if (proxyValues == null)
				return;
			proxyName = proxyValues[0];
			proxyPort = Integer.parseInt(proxyValues[1]);
			VM.setSystemProperty("http.proxyHost", proxyName);
			VM.setSystemProperty("http.proxyPort", proxyValues[1]);
		}
	}

	public InputStream openInputStream() throws IOException {
		if (conClosed)
			throw new IOException(Msg.getString("K00ac"));
		if (inputStatus != 0) {
			throw new IOException(Msg.getString("K0192"));
		} else {
			doRequest();
			inputStatus = 1;
			return new InputStream() {

				public int available() throws IOException {
					if (inputStatus == 2)
						throw new IOException(Msg.getString("K0059"));
					else
						return uis.available();
				}

				public int read() throws IOException {
					if (inputStatus == 2)
						throw new IOException(Msg.getString("K0059"));
					else
						return uis.read();
				}

				public int read(byte buf[], int offset, int length) throws IOException {
					if (inputStatus == 2)
						throw new IOException(Msg.getString("K0059"));
					else
						return uis.read(buf, offset, length);
				}

				public long skip(long amount) throws IOException {
					if (inputStatus == 2)
						throw new IOException(Msg.getString("K0059"));
					else
						return uis.skip(amount);
				}

				public void close() throws IOException {
					if (inputStatus != 2) {
						inputStatus = 2;
						closeSocket();
					}
				}

			};
		}
	}

	private InputStream getContentStream() throws IOException {
		String encoding = resHeader.get("Transfer-Encoding");
		if (encoding != null && encoding.toLowerCase().equals("chunked"))
			return uis = new ChunkedInputStream();
		String sLength = resHeader.get("Content-Length");
		if (sLength != null)
			try {
				int length = Integer.parseInt(sLength);
				return uis = new LimitedInputStream(length);
			} catch (NumberFormatException _ex) {
			}
		return uis = is;
	}

	public OutputStream openOutputStream() throws IOException {
		if (conClosed)
			throw new IOException(Msg.getString("K00ac"));
		if (access != 2 && access != 3)
			throw new IOException(Msg.getString("K00aa"));
		if (sentRequest && os == null)
			throw new IOException(Msg.getString("K0037"));
		if (outputStatus != 0)
			throw new IOException(Msg.getString("K0192"));
		if (os == null) {
			method = "POST";
			String encoding = reqHeader.get("Transfer-Encoding");
			if (encoding != null)
				encoding = encoding.toLowerCase();
			os = new HttpOutputStream(sendChunked || "chunked".equals(encoding));
		}
		outputStatus = 1;
		return new OutputStream() {

			public void write(int value) throws IOException {
				if (outputStatus == 2) {
					throw new IOException(Msg.getString("K0059"));
				} else {
					os.write(value);
					return;
				}
			}

			public void write(byte buf[], int offset, int length) throws IOException {
				if (outputStatus == 2) {
					throw new IOException(Msg.getString("K0059"));
				} else {
					os.write(buf, offset, length);
					return;
				}
			}

			public void flush() throws IOException {
				if (outputStatus == 2) {
					throw new IOException(Msg.getString("K0059"));
				} else {
					os.flush();
					return;
				}
			}

			public void close() throws IOException {
				if (outputStatus != 2) {
					outputStatus = 2;
					os.close();
				}
			}

		};
	}

	private String requestString() {
		if (proxyName != null)
			return getURL();
		else
			return file != null ? file : "/";
	}

	protected String getHostName() {
		if (proxyName != null)
			return proxyName;
		else
			return getHost();
	}

	protected int getHostPort() {
		if (proxyName != null)
			return proxyPort;
		else
			return getPort();
	}

	public long getLength() {
		try {
			String sLength = getHeaderField("Content-Length");
			if (sLength == null)
				return -1L;
			else
				return Long.parseLong(sLength);
		} catch (IOException _ex) {
			return -1L;
		} catch (NumberFormatException _ex) {
			return -1L;
		}
	}

	public String getEncoding() {
		try {
			return getHeaderField("Content-Encoding");
		} catch (IOException _ex) {
			return null;
		}
	}

	public String getType() {
		try {
			return getHeaderField("Content-Type");
		} catch (IOException _ex) {
			return null;
		}
	}

	protected boolean isClosed() {
		return conClosed;
	}

}