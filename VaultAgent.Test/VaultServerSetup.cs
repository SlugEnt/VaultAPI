using System;
using System.Net.Sockets;
using System.Collections.Generic;
using System.Text;
using System.Diagnostics;
using System.Net;
using System.IO;
using NUnit.Framework;
using System.Reflection;
using System;
namespace VaultAgentTests
{
	/// <summary>
	/// Static class used by all the other test methods to communicate with the Vault server that has been started in dev mode.
	/// </summary>
	public static class VaultServerRef
	{
		public static string rootToken;
		public static System.Uri vaultURI;
		public static string ipAddress;
		public static string vaultFolder;
		public static string unSealKey;
	}




	/// <summary>
	/// Performs Unit Test first time setup of the Vault server.  
	///   - Starts the vault server in Dev mode, with a known root token.
	///   - Scans the startup process to look for the unseal key.
	/// </summary>
	[SetUpFixture]
	public class VaultServerSetup : IDisposable {
		private Process _process;
		private bool _disposed;

	
		
		[OneTimeSetUp]
		public void StartVaultServer() {

			VaultServerRef.rootToken = Guid.NewGuid().ToString();
			VaultServerRef.ipAddress = $"127.0.0.1:{ GetRandomUnusedPort() }";
			VaultServerRef.vaultURI  =  new Uri("http://" + VaultServerRef.ipAddress);
			VaultServerRef.vaultFolder = GetTestsPath() + "\\Utility";


			var vaultArgs = string.Join(" ", new List<string>
			{
				"server",
				"-dev",
				$"-dev-root-token-id={VaultServerRef.rootToken}",
				$"-dev-listen-address={VaultServerRef.ipAddress}"
			});


			// Define the shell environment for the vault server.  Vault.Exe should be in a subdirectory off 
			// of this projects main folder.  Subdirectory should be called Utility.
			string vaultBin = "vault.exe";
			string vaultFullBin = VaultServerRef.vaultFolder + "\\" + vaultBin;

			var startInfo = new ProcessStartInfo(vaultFullBin, vaultArgs) { UseShellExecute = false };

			// Startup the vault server
			startInfo.EnvironmentVariables["HOME"] = VaultServerRef.vaultFolder;

			// Disables ansi color problems in vault 0.9.6.  This is work around.
			startInfo.EnvironmentVariables["VAULT_CLI_NO_COLOR"] = "4";


			// Build the process
			_process = new Process {
				StartInfo = startInfo
			};
			_process.StartInfo.RedirectStandardOutput = true;
			_process.StartInfo.RedirectStandardError = true;


			if (!_process.Start()) {
				throw new Exception($"Process did not start successfully: {_process.StandardError}");
			}


			// Now look for successful start message.
			var line = _process.StandardOutput.ReadLine();
			while (line?.StartsWith("==> Vault server started!") == false) {
				if (line?.StartsWith("Unseal Key:") == true) {
					VaultServerRef.unSealKey = line.Substring("Unseal Key:".Length+1);
				}
				line = _process.StandardOutput.ReadLine();
			}

			if (_process.HasExited) {
				throw new Exception($"Process could not be started: {_process.StandardError}");
			}
		}

		[OneTimeTearDown]
		public void StopVaultServer() {
			_process.CloseMainWindow();
			_process.Kill();
		}




		/// <summary>
		/// Used to get the path to the Utility folder which is where vault.exe needs to be placed and any files the test
		/// scripts need to process.
		/// </summary>
		/// <returns></returns>
		public static string GetTestsPath() {
			string sPath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().CodeBase);
			int i = sPath.LastIndexOf("\\bin");
			if (i > 0) { sPath = sPath.Substring(0, i);  }
			else {
				throw new Exception("Unable to locate bin directory of the test executable.  Need this to find Vault directory");
			}

			// Strip off the beginning
			sPath = sPath.Replace("file:\\", "");
			return sPath;		
		}




		/// <summary>
		/// Acquires an IP Address port that is not currently used.
		/// </summary>
		/// <returns></returns>
		private static int GetRandomUnusedPort() {
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
		protected virtual void Dispose(bool disposing) {
			if (_disposed) {
				return;
			}

			if (disposing) {
				try {
					_process.CloseMainWindow();
					_process.Kill();
				}
				catch { }
				_process.Dispose();
			}

			_disposed = true;
		}

		public void Dispose() {
			Dispose(true);
		}
	}
}
