DEVICE=lo

server.o: icmp-server.c
	clang -m64 -O2 -target bpf -I/usr/include/ -c $< -o $@

qdisc:
	sudo tc qdisc add dev $(DEVICE) ingress handle ffff:
qdisc-delete:
	sudo tc qdisc delete dev $(DEVICE) ingress
run: bpf.o
	sudo tc filter add dev $(DEVICE) parent ffff: bpf obj server.o sec classifier flowid ffff:1 \
		action bpf obj icmp-server.o sec action ok
delete:
	sudo tc filter delete dev $(DEVICE) parent ffff:
show:
	sudo tc filter show dev $(DEVICE) ingress

exec:
	sudo tc exec bpf dbg
