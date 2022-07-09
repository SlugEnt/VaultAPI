using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using VaultAgent;
using VaultAgentTests;

namespace VaultAgentTests
{
	/// <summary>
	/// This class exists purely to start up Vault or to connect to an existing already running version of Vault for Testing purposes.
	/// </summary>
	[SetUpFixture]
	public class SetupInitializer : IDisposable
	{
		// Set this flag to false if you do not want a new Vault instance started during each test run.  
		// This can be useful if you want to be able to connect PostMan to the vault server to query for data to get a better handle on what is going on.
		// Also, you can see the log files, etc.
		private readonly bool UseNewVaultServerEachRun = true;
		private readonly bool UseRandomPort = false;

		// The new Vault instance object if we needed to create it.
		private VaultServerInstance VSI;

		private bool _disposed = false;


		public SetupInitializer() { }



		[OneTimeSetUp]
		public async Task InitTestingSetup()
		{
			if (UseNewVaultServerEachRun == true)
			{
				// Startup new Vault instance each run
				VaultServerRef.rootToken = "testing";
				VaultServerRef.ipAddress = "127.0.0.1";

				if (UseRandomPort)
					VaultServerRef.ipPort = GetRandomUnusedPort();
				else
					VaultServerRef.ipPort = 57678;
			}
			else
			{
				// Connect to an already running Vault instance.
				VaultServerRef.rootToken = "tokenA";
				VaultServerRef.ipAddress = "127.0.0.1";
				VaultServerRef.ipPort = 16101;
			}

			VaultServerRef.vaultFolder = "C:\\A_Dev\\Utilities\\";
			VaultServerRef.vaultURI = new Uri("http://" + VaultServerRef.ipAddress + ":" + VaultServerRef.ipPort);

			// See if Vault already running on that port / URI
			try
			{
				VaultAgentAPI vault = await VaultServerRef.ConnectVault("AppRoleVault");
			}
			catch (Exception e)
			{
				// Now startup the Vault instance if we need to.
				if (UseNewVaultServerEachRun)
				{
					VSI = new VaultServerInstance();
					VSI.StartVaultServer();
				}
			}

		}



		/// <summary>
		/// Acquires an IP Address port that is not currently used.
		/// </summary>
		/// <returns></returns>
		private static int GetRandomUnusedPort()
		{
			var listener = new TcpListener(IPAddress.Any, 0);
			listener.Start();
			var port = ((IPEndPoint)listener.LocalEndpoint).Port;
			listener.Stop();
			return port;
		}



		/// <summary>
		/// Ensures the Vault process is stopped.
		/// </summary>
		/// <param name="disposing"></param>
		protected virtual void Dispose(bool disposing)
		{
			if ((_disposed) || (VSI == null))
			{
				return;
			}

			if (disposing)
			{
				try
				{
					VSI.StopVaultServer();
				}
				catch { }
			}

			_disposed = true;
		}



		[OneTimeTearDown]
		public void Dispose()
		{
			GC.SuppressFinalize(this);
			Dispose(true);
		}

	}
}
