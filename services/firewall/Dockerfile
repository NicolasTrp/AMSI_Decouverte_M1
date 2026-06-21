FROM debian:trixie-slim

# Routeur/pare-feu : iptables (conntrack), iproute2, diagnostic, + tinyproxy
# (egress LAN contrôlé). Le firewall n'expose aucun service : il route et filtre.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        iptables \
        iproute2 \
        conntrack \
        procps \
        iputils-ping \
        tinyproxy \
 && rm -rf /var/lib/apt/lists/*

COPY firewall.sh /usr/local/bin/firewall.sh
RUN chmod +x /usr/local/bin/firewall.sh

ENTRYPOINT ["/usr/local/bin/firewall.sh"]
