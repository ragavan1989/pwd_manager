python vault.py --usage

    🔐 Password Vault - Command Line Usage

    Usage:
      python vault.py [command] [options]

    Commands:
      --usage             Show this help message
      add <site>          Add a new password entry for the site
      get <site>          Retrieve the password for the site
      list                List all stored entries
      delete <site>       Delete password entry for the site

    Notes:
    - Your vault is encrypted with AES-256 GCM.
    - The master password is never stored and must be entered every time.
    - Everything is local and secure.

    Example:
      python vault.py add gmail
      python vault.py get gmail
