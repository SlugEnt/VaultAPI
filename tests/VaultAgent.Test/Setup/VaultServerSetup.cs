using System;
using System.Net.Sockets;
using System.Collections.Generic;
using System.Text;
using System.Diagnostics;
using System.Net;
using System.IO;
using NUnit.Framework;
using System.Reflection;
using VaultAgent;
using System.Threading;
using System.Threading.Tasks;
using VaultAgent.AuthenticationEngines;
using VaultAgent.AuthenticationEngines.LoginConnectors;



// NOTE:  The only thing you ever really need to change here is the UseNewVaultServerEachRun variable in the TestInitializer class. 
//   Set to True to use a new Vault development instance each time the tests are run.
//   Set to False to use an already running Vault instance.  For instance, we have a standard Vault Development instance that can 
//   be started and then left running thru multiple tests scenarios.  Useful when you need to debug with Postman or just want a slight
//   speedup in starting up each test run.  
//
// NOTE: It is up to the UnitTestCases to ensure they can handle such a scenario by creating unique keys each test run.


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
		public static int ipPort;


        /// <summary>
        /// Creates a Vault instance and connects it with either the default testing token or the specified token
        /// </summary>
        /// <param name="name">Name to be given to this Vault object</param>
        /// <param name="overrideToken">The TokenId to use if you do not wish to use the default testing token</param>
        /// <returns></returns>
        public static async Task<VaultAgentAPI> ConnectVault (string name, string overrideToken = "") {
            vaultURI = new Uri("http://"+ ipAddress + ":" + ipPort);
            VaultAgentAPI vault = new VaultAgentAPI(name,vaultURI);

            string thisToken;
            if ( overrideToken != string.Empty )
                thisToken = overrideToken;
            else
                thisToken = rootToken;

            TokenLoginConnector loginConnector = new TokenLoginConnector(vault,"Testing",thisToken,TokenAuthEngine.TOKEN_DEFAULT_MOUNT_NAME);
            bool success = await loginConnector.Connect();
            if ( !success) throw new ApplicationException("Error connecting to the Vault Instance using Token " + thisToken);
            return vault;
        }
	}



	



	/// <summary>
	/// Performs Unit Test first time setup of the Vault server.  
	///   - Starts the vault server in Dev mode, with a known root token.
	///   - Scans the startup process to look for the unseal key.
	/// </summary>
	public class VaultServerInstance : IDisposable {
		private Process _process;
		private bool _disposed;

		private static bool _startingUP = true;

		public VaultServerInstance() { }



		// Starts up an instance of Vault for development and testing purposes.
		public void StartVaultServer() {
			var vaultArgs = string.Join(" ", new List<string>
			{
				"server",
				"-dev",
				$"-dev-root-token-id={VaultServerRef.rootToken}",
				$"-dev-listen-address={VaultServerRef.ipAddress}:{VaultServerRef.ipPort}",
				$"-log-level=trace"
			});


			// Define the shell environment for the vault server.  Vault.Exe should be in a subdirectory off 
			// of this projects main folder.  Subdirectory should be called Utility.
			string vaultBin = "vault.exe";
			string vaultFullBin = VaultServerRef.vaultFolder + vaultBin;

			var startInfo = new ProcessStartInfo(vaultFullBin, vaultArgs) {
				UseShellExecute = false,
				WindowStyle = ProcessWindowStyle.Normal,
				CreateNoWindow = false,
				RedirectStandardError = true,
				RedirectStandardOutput = true
			};

			// Startup the vault server
			startInfo.EnvironmentVariables["HOME"] = VaultServerRef.vaultFolder;

			// Disables ansi color problems in vault 0.9.6.  This is work around.
			startInfo.EnvironmentVariables["VAULT_CLI_NO_COLOR"] = "4";


			// Build the process
			_process = new Process {
				StartInfo = startInfo
			};


			_process.OutputDataReceived += (sender, eventArgs) => CaptureOutput(sender, eventArgs);
			_process.ErrorDataReceived += (sender, eventArgs) => CaptureError(sender, eventArgs);


			if (!_process.Start()) {
				throw new Exception($"Process did not start successfully: {_process.StandardError}");
			}
			_process.BeginErrorReadLine();
			_process.BeginOutputReadLine();


			while (VaultServerInstance._startingUP == true) {
				Thread.Sleep(10);				
			}


			if (_process.HasExited) {
				throw new Exception($"Process could not be started: {_process.StandardError}");
			}
		}


		public void StopVaultServer() {
			_process.CloseMainWindow();
			_process.Kill();
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



		// Following methods are used to output Vault messages to the Debug window.

		static void CaptureOutput(object sender, DataReceivedEventArgs e) {
			ShowOutput(e.Data, true);
		}

		static void CaptureError(object sender, DataReceivedEventArgs e) {
			ShowOutput(e.Data, false);
		}

		static void ShowOutput(string data, bool stdOutput) {
			string cat;
			if (stdOutput) { cat = "Vault"; }
			else { cat = "VERR"; }


			// Write the line to the Debug window.
			Debug.WriteLine(data,cat);

			// If starting up then we need to look for some stuff.
			if (VaultServerInstance._startingUP) {
				// Now look for successful start message.
				if (data?.StartsWith("==> Vault server started!") == true) {
					VaultServerInstance._startingUP = false;
					return;
				}
				if (data?.StartsWith("Unseal Key:") == true) {
					VaultServerRef.unSealKey = data.Substring("Unseal Key:".Length + 1);
				}
			}

		}
			
	}
}
