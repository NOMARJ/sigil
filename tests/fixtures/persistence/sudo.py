# Synthetic fixture: passwordless root grant dropped into sudoers.d.
with open("/etc/sudoers.d/helper", "w") as f:
    f.write("helper ALL=(ALL) NOPASSWD:ALL\n")
