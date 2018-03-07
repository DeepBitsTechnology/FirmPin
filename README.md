###TriforceAFL_new

A tool for simulation, dynamic analsis and fuzz of IoT firmware. \<br>
Combination of TriforceAFL, firmadyne and DECAF. \<br>

####Firmadyne: we use its custom kernel and libnvram. 
  cd firmadyne \<br>
  See README in firmadyne and do as it says. \<br>
  Here, we test DIR-815_FIRMWARE_1.01.ZIP, a router firmware image based on mipsel cpu arch. \<br>
  Finally, we replace the run.sh in scratch/(num)/ with our modified one. \<br>

####TriforceAFL: 
  run make \
  
####DECAF: upgraded to the newest qemu version 2.10.1
   It is included in qemu_mode/qemu dir. \<br>
   If there is something wrong with sleuthkit, plese comment or not comment the following code. \<br>
	LIBS="\$(SRC_PATH)/shared/sleuthkit/lib/libtsk.a -lbfd $LIBS" \<br>

   In our case, run ./configure --target-list=mipsel-softmmu \<br>
   run make \<br>



