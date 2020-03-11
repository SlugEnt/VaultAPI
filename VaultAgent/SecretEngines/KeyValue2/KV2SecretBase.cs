using System;
using System.Collections.Generic;
using Newtonsoft.Json;



namespace VaultAgent.SecretEngines.KeyValue2
{
    /// <summary>
    /// Abstract class for a KeyValue 2 Secret object. 
    /// </summary>

    public abstract class KV2SecretBase<T> : ICloneable, IKV2Secret, IComparable<T> where T : KV2SecretBase<T>
    {
        // The path to the secret in the Vault Instance
            private string _path;

            // The name of the secret object in the Vault Instance.
            private string _name;

            //TODO - Does name and path need to be only set thru constructor - even in JSON constructions?  
            //TODO - Do we need a Key value which returns what the key of this secret would be (Name+Path)?

            
            /// <summary>
            /// Creates a new empty secret
            /// </summary>
            [JsonConstructor]
            public KV2SecretBase() { Attributes = new Dictionary<string, string>(); }



            /// <summary>
            /// Creates a new secret with the specified Name (Path)
            /// </summary>
            /// <param name="secretName">The name of the secret.</param>
            /// <param name="path">The path to the secret to be stored.  apps/appA/config   apps/appA is the path.</param>
            public KV2SecretBase(string secretName, string path = "")
            {
                Name = secretName;

                if (path.StartsWith("/data/"))
                {
                    throw new ArgumentException("KeyValue V2 secret paths do not need to specify the /data/ prefix as it is assumed.");
                }

                Path = path;
                Attributes = new Dictionary<string, string>();
            }



            /// <summary>
            /// The name of the secret.  In Vault terminology this is the very last part of the secret path.  So if a secret is stored at
            /// app/AppA/username  then the secret name would be username and the secret path would be app/AppA.  
            /// </summary>
            public string Name
            {
                get => _name;

                //TODO - Does this need to be an internal set?
                set { _name = value; }
            }


            /// <summary>
            /// The path where the secret should be stored.  So if a secret is stored at app/AppA/username then the secret path would be app/AppA.
            /// Note:  All leading and trailing slashes are removed from the passed in value.
            /// </summary>
            public string Path
            {
                get { return _path; }

                //TODO - Does this need to be an internal set? 
                set
                {
                    if (value == "/") { _path = ""; }
                    else { _path = value.TrimEnd('/').TrimStart(('/')); }
                }
            }



            /// <summary>
            /// Returns the FullPath to the Secret.  The Fullpath is the path plus the Name of the secret.  So, Path1/path2/path3/secretName
            /// </summary>
            public string FullPath
            {
                get
                {
                    if (_path == "") { return Name; }

                    return (Path + "/" + Name);
                }
            }


            /// <summary>
            /// Returns True if the Secret was read from Vault, False if it was created outside of Vault.
            /// </summary>
            public bool WasReadFromVault
            {
                get { return Version > 0 ? true : false; }
            }



            /// <summary>
            /// The actual values that should be saved in the secret. 
            /// </summary>
            [JsonProperty("data")]
            public Dictionary<string, string> Attributes { get; set; }



            /// <summary>
            /// MetaData associated with the secret.
            /// </summary>
            [JsonProperty("metadata")]
            public Dictionary<string, string> Metadata { get; set; }



            // Extended Attributes


            /// <summary>
            /// When the secret was actually saved to the Vault data store.  
            /// </summary>
            public DateTimeOffset CreatedTime { get; internal set; }


            /// <summary>
            /// When this particular secret version was deleted from the Vault data store.
            /// </summary>
            public DateTimeOffset DeletionTime { get; internal set; }


            /// <summary>
            /// Boolean - Whether this particular secret version is soft deleted or destroyed.  True means this secret data cannot be undeleted.
            /// </summary>
            public bool IsDestroyed { get; internal set; }


            /// <summary>
            /// The version number of this particular secret.  Is > 0 if the secret was read from the Vault.  Is zero if this object was created in application.
            /// </summary>
            public int Version { get; internal set; } = 0;



            /// <summary>
            /// Returns the Path that this secret belongs to.
            /// </summary>
            /// <returns></returns>
            public string GetParentPath()
            {
                int pos = FullPath.LastIndexOf('/');
                if (pos < 1)
                {
                    return "/";
                }
                
                string value = FullPath.Substring(0, pos);


                return value;
            }


            #region "EqualityComparers"


            /// <summary>
            /// Determines if 2 KV2Secrets are the same.  Same is defined as: same name, path, number of attributes, and same attribute names and values.
            /// Does not evaluate any metadata or Version attributes.
            /// </summary>
            /// <param name="s"></param>
            /// <returns></returns>
            public override bool Equals(Object s)
            {
                // If S is null then !=
                if (ReferenceEquals(s, null)) { return false; }

                // Optimization for common success case where references are same.
                if (ReferenceEquals(this, s)) { return true; }

                // If not of the exact same class type.
                if (this.GetType() != s.GetType()) { return false; }

                // Ensure the object is of the same type as this object
                if (s.GetType().BaseType != GetType().BaseType) return false;

                // Ok now need to do field matching.
                KV2SecretBase<T> ss = (KV2SecretBase<T>)s;
                if (this.Attributes.Count != ss.Attributes.Count) { return false; }

                if (this.FullPath != ss.FullPath) { return false; }

                // Now validate the Attributes are exactly the same.
                foreach (KeyValuePair<string, string> a in this.Attributes)
                {
                    string val;
                    if (ss.Attributes.TryGetValue(a.Key, out val))
                    {
                        if (a.Value != val) { return false; }
                    }
                    else { return false; }
                }

                return true;
            }


            /// <summary>
            /// Equality == 
            /// </summary>
            /// <param name="left"></param>
            /// <param name="right"></param>
            /// <returns></returns>
            public static bool operator ==(KV2SecretBase<T> left, KV2SecretBase<T> right)
            {
                if (ReferenceEquals(left, null))
                {
                    if (ReferenceEquals(right, null)) { return true; }

                    return false;
                }

                return left.Equals(right);
            }


            /// <summary>
            /// Compares 2 objects to see if equal.
            /// </summary>
            /// <typeparam name="T"></typeparam>
            /// <param name="a"></param>
            /// <param name="b"></param>
            /// <returns></returns>
            public bool Compare<T>(T a, T b) where T : class, IKV2Secret
            {
                return a == b;
            }



            /// <summary>
            /// Not Equal comparison
            /// </summary>
            /// <param name="left"></param>
            /// <param name="right"></param>
            /// <returns></returns>
            public static bool operator !=(KV2SecretBase<T> left, KV2SecretBase<T> right) { return !(left == right); }


            /// <summary>
            /// Returns the hash code of the secret which is the FullPath
            /// </summary>
            /// <returns></returns>
            public override int GetHashCode() { return this.FullPath.GetHashCode(); }


            /// <summary>
            /// Clones the secret to a new secret.
            /// </summary>
            /// <returns></returns>
            public object Clone()
            {
                // Perform a deep clone.
                KV2SecretBase<T> copy = (KV2SecretBase<T>)MemberwiseClone();

                // Copy the attributes
                if (Attributes != null)
                {
                    copy.Attributes = new Dictionary<string, string>();
                    foreach (KeyValuePair<string, string> attr in Attributes) { copy.Attributes.Add(attr.Key, attr.Value); }
                }

                // Copy the MetaData
                if (Metadata != null)
                {
                    copy.Metadata = new Dictionary<string, string>();
                    foreach (KeyValuePair<string, string> meta in Metadata) { copy.Metadata.Add(meta.Key, meta.Value); }
                }

                return copy;
            }


            /// <summary>
            /// Implements the CompareTo function using the FullPath as the comparison
            /// </summary>
            /// <param name="other"></param>
            /// <returns></returns>
            public int CompareTo(T other)
            {
                return FullPath.CompareTo(other.FullPath);
            }



        #endregion
    }
}
