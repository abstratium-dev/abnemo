#!/bin/bash
# Export Docker information for iptables visualization
# Run this script on the remote server and paste the output along with iptables rules

echo "=== DOCKER ENRICHMENT DATA ==="
echo ""

echo "# Docker Containers"
echo "# Format: IP|ContainerName|NetworkName|Gateway"
docker ps -a --format '{{.ID}}' 2>/dev/null | while read container_id; do
    docker inspect "$container_id" 2>/dev/null | jq -r '
        .[0] as $container |
        $container.NetworkSettings.Networks | to_entries[] | 
        "\(.value.IPAddress)|\($container.Name[1:])|\(.key)|\(.value.Gateway)"
    ' 2>/dev/null
done | grep -v '^|' | sort -u

echo ""
echo "# Docker Networks"
echo "# Format: NetworkName|Subnet|Gateway|Driver|InterfaceID"
docker network ls --format '{{.ID}}' 2>/dev/null | while read network_id; do
    docker network inspect "$network_id" 2>/dev/null | jq -r '
        .[0] | 
        .Name as $name | 
        .Driver as $driver |
        .Id[0:12] as $id |
        (.IPAM.Config // []) | .[] |
        "\($name)|\(.Subnet)|\(.Gateway)|\($driver)|\($id)"
    ' 2>/dev/null
done | grep -v '^|' | sort -u

echo ""
echo "=== END DOCKER ENRICHMENT DATA ==="
echo ""
echo "# Now run: sudo iptables -L -v -n"
echo "# Copy everything above AND the iptables output to the visualizer"
