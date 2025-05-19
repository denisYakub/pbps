INSTALL_DIR=/usr/local/bin
SERVICE_FILE=/etc/systemd/system/PICOFoxweb.service

all: PICOFoxweb

clean:
	@rm -rf *.o
	@rm -rf PICOFoxweb

PICOFoxweb: main.o httpd.o
	gcc -o PICOFoxweb $^

main.o: main.c httpd.h
	gcc -c -o main.o main.c

httpd.o: httpd.c httpd.h
	gcc -c -o httpd.o httpd.c

install: PICOFoxweb
	install -m 755 PICOFoxweb $(INSTALL_DIR)
	install -m 644 PICOFoxweb.service $(SERVICE_FILE)
	systemctl daemon-reexec
	systemctl daemon-reload
	systemctl enable PICOFoxweb.service
	systemctl start PICOFoxweb.service
	@echo "Service installed and started."

uninstall:
	systemctl stop PICOFoxweb.service || true
	systemctl disable PICOFoxweb.service || true
	rm -f $(SERVICE_FILE)
	rm -f $(INSTALL_DIR)/PICOFoxweb
	systemctl daemon-reload
	@echo "Service uninstalled."
