
namespace VaultAgent.Backends.System
{
	public class VaultPolicyItem
	{
		private bool createAllowed = false;
		private bool readAllowed = false;
		private bool updateAllowed = false;
		private bool deleteAllowed = false;
		private bool listAllowed = false;
		private bool sudoAllowed = false;
		private bool rootAllowed = false;
		private bool denied = true;


		/// <summary>
		/// All VaultPolicyItem objects are initialized in denied = True state.
		/// </summary>
		public VaultPolicyItem (string path) { Path = path; }

		public string Path { get; set; }

		public bool CreateAllowed {
			get { return createAllowed; }
			set {
				denied = false;
				createAllowed = value;
			}
		}

		public bool ReadAllowed
		{
			get { return readAllowed; }
			set {
				denied = false;
				readAllowed = value;
			}
		}

		public bool UpdateAllowed
		{
			get { return updateAllowed; }
			set {
				denied = false;
				updateAllowed = value;
			}
		}

		public bool DeleteAllowed
		{
			get { return deleteAllowed; }
			set {
				denied = false;
				deleteAllowed = value;
			}
		}
		public bool ListAllowed
		{
			get { return listAllowed; }
			set {
				denied = false;
				listAllowed = value;
			}
		}
		public bool SudoAllowed
		{
			get { return sudoAllowed; }
			set {
				denied = false;
				sudoAllowed = value;
			}
		}

		public bool RootAllowed
		{
			get { return rootAllowed; }
			set {
				denied = false;
				rootAllowed = value;
			}
		}

	/// <summary>
	/// Either sets denied property or cancels it.  If setting Denied to True, then ALL other permissions are set to False.  
	/// If setting denied to false and it was True, then none of the other permissions are changed (they remain false), you must manually enable the ones you want.
	/// </summary>
	public bool Denied
		{
			get { return denied; }
			set {
				// If no change do nothing.
				if (denied == value) { return; }

				if (denied) {
					createAllowed = false;
					readAllowed = false;
					updateAllowed = false;
					deleteAllowed = false;
					listAllowed = false;
					sudoAllowed = false;
					rootAllowed = false;
				}
			}
		}









	}
}
