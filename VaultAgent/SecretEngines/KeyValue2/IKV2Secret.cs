using System;
using System.Collections.Generic;
using System.Text;

namespace VaultAgent.SecretEngines.KeyValue2
{
    public interface IKV2Secret
    {
        string Name { get; set; }
        string Path { get; set; }
        string FullPath { get; }
        bool WasReadFromVault { get; }
        Dictionary<string, string> Attributes { get; set; }
        Dictionary<string, string> Metadata { get; set; }
        DateTimeOffset CreatedTime { get; }
        string DeletionTime { get; }
        bool Destroyed { get;   }
        int Version { get;  }
    }
}
