from pp_clsag_core import keygen_from_seed, key_image, rep_commitment, sign_schnorr, verify_schnorr

seed = b"demo-seed-32-bytes-length....."[:32]
D = b"credential-digest-32-bytes......"[:32]
sk, pk = keygen_from_seed(seed, D)
print("sk len", len(sk), "pk len", len(pk))
print("sk bytes:", sk)
print("pk bytes:", pk)
skb = bytes(sk)
pkb = bytes(pk)

# context-bound tag
tag = key_image(skb, pkb, b"context-42")
print("tag (hex):", bytes(tag).hex())

# reputation commitment
comm = rep_commitment(pkb, 4)
print("rep commitment (hex):", bytes(comm).hex())

# schnorr
R, s = sign_schnorr(b"hello", skb)
print("R (hex):", bytes(R).hex())
print("s (hex):", bytes(s).hex())
print("verify:", verify_schnorr(b"hello", pkb, bytes(R), bytes(s)))
print("verify-wrong:", verify_schnorr(b"bye", pkb, bytes(R), bytes(s)))