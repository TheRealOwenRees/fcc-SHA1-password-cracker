import hashlib

def crack_sha1_hash(hash, use_salts=False):

  # salted hash cracker
  def salted_hash(passwords):
    with open("known-salts.txt") as f:
      salts = f.readlines()

      # for every password append/prepend salt before hashing
      for password in passwords:
        password = password.strip("\n")
        for salt in salts:
          salt = salt.strip("\n")
          pwsalted_prepend = f"{salt}{password}"
          pwsalted_append = f"{password}{salt}"
          pwsaltedhash1 = hashlib.sha1(pwsalted_prepend.encode()).hexdigest()
          pwsaltedhash2 = hashlib.sha1(pwsalted_append.encode()).hexdigest()
          if pwsaltedhash1 == hash or pwsaltedhash2 == hash:
            return password
    return "PASSWORD NOT IN DATABASE"

  # unsalted hash cracker
  def unsalted_hash(passwords):
    for password in passwords:
      password = password.strip("\n")
      pwhash = hashlib.sha1(password.encode()).hexdigest()
      if pwhash == hash:
        return password
    return "PASSWORD NOT IN DATABASE"

  # open password file and pass to salted/unsalted functions
  with open("top-10000-passwords.txt") as f:
    passwords = f.readlines()
 
  return salted_hash(passwords) if use_salts else unsalted_hash(passwords)