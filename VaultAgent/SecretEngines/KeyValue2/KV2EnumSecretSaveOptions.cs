using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultAgent.Backends {
    public enum KV2EnumSecretSaveOptions { OnlyIfKeyDoesNotExist = 0, OnlyOnExistingVersionMatch = 1, AlwaysAllow = 2 }
}