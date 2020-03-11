﻿using System;
using System.IO;
using System.Threading.Tasks;
using Newtonsoft.Json;
using VaultAgent;
using VaultAgent.AuthenticationEngines;
using VaultAgent.AuthenticationEngines.LoginConnectors;
using VaultAgent.Backends;
using VaultAgent.Models;


namespace VaultClient
{
	class Program
	{
		public static async Task Main(string[] args) {

			string rootToken;
			
			string ip;
			int port;

			// Use local dev server.
			rootToken = "tokenA";
            ip = "127.0.0.1";
			port = 16100;

			// Connect to Vault, add an authentication backend of AppRole.
            VaultAgentAPI vaultAgent = new VaultAgentAPI("VaultClient",ip,port);
            TokenLoginConnector loginConnector = new TokenLoginConnector(vaultAgent,"Client",rootToken,TokenAuthEngine.TOKEN_DEFAULT_MOUNT_NAME);
            bool success = await loginConnector.Connect();

			//VaultAgentAPI vaultAgent = await VaultServerRef.ConnectVault("AppRoleVault");
            //new VaultAgentAPI("Vault", ip, port, rootToken, true);


            InitiateVault initiateVault = new InitiateVault(vaultAgent);
            await initiateVault.WipeVault();
            await initiateVault.InitialSetup();

            // This Client Requires AD Credentials
            string config = await initiateVault.GetConfig();
            await initiateVault.Login();



            // Run the Policy Secret Tutorial Example
            PolicyRoleSecurityExample policySecretExample = new PolicyRoleSecurityExample(vaultAgent);
            await policySecretExample.Run();


			// Sample Scenarios determine which of the below to run.
			// 1 = Optimize Scenario
			// 2 = AppRole Scenario
			// 3 = System Backend Scenario
			// 4 = Transit Scenario

			int runSampleScenario = 4;

            // Perform optimize tests
            switch ( runSampleScenario ) {
				case 1:
					OptimizeTests optimize = new OptimizeTests(vaultAgent);
					await optimize.Run();
					break;
				case 2: 
					VC_AppRoleAuthEngine roleBE = new VC_AppRoleAuthEngine(vaultAgent);
					await roleBE.Run();
					break;
				case 3:
					// System Backend Examples:
					VaultClient_SystemBackend sysBE = new VaultClient_SystemBackend(rootToken, ip, port);
					await sysBE.Run();
					break;
				case 4:
					// Transit Backend
					string transitDB = "transit";
					VaultClient_TransitBackend transit = new VaultClient_TransitBackend(rootToken, ip, port, transitDB);
					await transit.Run();
					break;
            }

			Console.WriteLine("Finished with all sample runs.");
			Console.WriteLine("  -- Press any key to exit program.");
			Console.ReadKey();
		}
	}
}
