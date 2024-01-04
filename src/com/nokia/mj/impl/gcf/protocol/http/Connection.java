/*
* Copyright (c) 2009 Nokia Corporation and/or its subsidiary(-ies).
* All rights reserved.
* This component and the accompanying materials are made available
* under the terms of "Eclipse Public License v1.0"
* which accompanies this distribution, and is available
* at the URL "http://www.eclipse.org/legal/epl-v10.html".
*
* Initial Contributors:
* Nokia Corporation - initial contribution.
*
* Contributors:
*
* Description:
*
*/

package com.nokia.mj.impl.gcf.protocol.http;

import com.nokia.mj.impl.gcf.utils.J9GcfConnectionBase;
import java.io.IOException;

public class Connection extends J9GcfConnectionBase
{
    private static Protocol iProtocol = null;

    public Connection()
    {
    }

    protected javax.microedition.io.Connection createConnection(String aName,
            int aMode, boolean aTimeouts) throws IOException
    {
    	int i = aName.indexOf(";nokia_http=1");
    	if(i != -1) {
    		aName = aName.substring(0, i) + aName.substring(i + 13);
            if (iProtocol == null)
            {
                iProtocol = new Protocol();
            }
            return iProtocol.openConnection(aName, aMode, aTimeouts);
    	}
    	return new HttpConnectionPatched().setParameters2(aName, aMode, aTimeouts);
    }
}