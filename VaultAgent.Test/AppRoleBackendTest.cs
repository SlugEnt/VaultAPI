using System;
using System.Collections.Generic;
using VaultAgent.Backends.AppRole;
using NUnit.Framework;


namespace VaultAgentTests
{
    public class AppRoleBackendTest
    {
		private AppRoleBackEnd _ARB;
		private object _arLocker;


		// Ensure Backend is initialized during each test.
		protected void AppBackendTestInit() {
			if (_ARB == null) {
				lock (_arLocker) {
					_ARB = new AppRoleBackEnd(VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken);
				}
			}
		}

	

	}
}
