using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Text;

namespace VaultAgent.SecretEngines.KeyValue2
{
    /// <summary>
    /// Interface for a KV2Secret Object functionality that derived objects must implement
    /// </summary>
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
        bool IsDestroyed { get;   }
        int Version { get;  }
    }
}
