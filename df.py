from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
parameters = dh.generate_parameters(generator=2, key_size=512,
                                     backend=default_backend())

alice_a = parameters.generate_private_key()  ## This is "a" for alice
alice_public_key = alice_a.public_key() ##This is g^a MOD P

bob_b = parameters.generate_private_key() ## This is "b" for Bob
bob_public_key = bob_b.public_key() ## This is g^b MOD p

alice_shared_key = alice_a.exchange(bob_public_key)
bob_shared_key = bob_b.exchange(alice_public_key)