for ((i = -25680; i < +22000; i++)) do TZ=Z printf '%s%(%Y%m%d)T' Aaron $((i*86400)) | md5sum ; done  |  grep -n 7f4986da7d7b52fa81f98278e6ec9dcb
29413:7f4986da7d7b52fa81f98278e6ec9dcb  -

# flag{Aaron29413}
