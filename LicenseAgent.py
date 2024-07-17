# IMPORTS


# 1. SEND (TID || ContentID) to LicenseServer


# 2. RECEIVE (T_LS || r || {Sig_LS( H(r || T-LS || T_U) || PK_U(License) || ContentID ) || Cert_LS}_K)


# 3. SEND ({Sig_U( H(T_U || T_LS || License) || token )}_K)

