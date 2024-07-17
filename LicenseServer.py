# IMPORTS


# 1. RECEIVE (TID || ContentID) to LicenseServer


# 2. SEND (T_LS || r || {Sig_LS( H(r || T-LS || T_U) || PK_U(License) || ContentID ) || Cert_LS}_K)


# 3. RECEIVE ({Sig_U( H(T_U || T_LS || License) || token )}_K)

