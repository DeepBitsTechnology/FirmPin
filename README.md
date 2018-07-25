###TriforceAFL_new

		A tool for simulation, dynamic analysis and fuzzing of IoT firmware.
		Combination of TriforceAFL, firmadyne and DECAF.

####Firmadyne: we use its custom kernel and libnvram to emulate IoT firmware. 
		cd firmadyne 
		See README in firmadyne and do as it says.
		Here, we test DIR-815_FIRMWARE_1.01.ZIP, a router firmware image based on mipsel cpu arch.
		Finally, we replace the run.sh in scratch/(num)/ with our modified one (In firmadyne_dev dir).

####DECAF: upgraded to the newest qemu version 2.10.1
		It is included in qemu_mode/qemu dir. 
		In our case, run ./configure --target-list=mipsel-softmmu
		Run make

####TriforceAFL: AFL fuzzing with full-system emulation
		Run make
  


####Usage:
		cd firmadyne
		Run ./scratch/(num)/run.sh (first replace it with ../firmadyne_dev/run.sh)
		In another terminal, run 'telnet 127.0.0.1 4444', into qemu monitor console.
		FirmFuzzer plugin:
			load_plugin ../qemu_mode/qemu/plugins/callbacktests/callbacktests.so
			do_callbacktests httpd
			do_callbacktests hedwig.cgi
			When firmware system initialization is completed and poll system call is executed, open a Browser, type a request "192.168.0.1/hedwig.cgi" in url, the fuzz process will be started.
		MalScalpel plugin:
			load_plugin ../qemu_mode/qemu/plugins/unpacker/unpacker.so
			trace_by_name mirai.mpsl
			Then, telnet into system "telnet 192.168.0.1" with username Alphanetworks and password wrgnd08_dlob_dir815
			Run "/FILE_LOAD/mirai.mpsl", the plugin works.



