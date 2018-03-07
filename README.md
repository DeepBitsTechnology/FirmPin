#TriforceAFL_new

A tool for simulation, dynamic analsis and fuzz of IoT firmware. \
Combination of TriforceAFL, firmadyne and DECAF. \

##Firmadyne: we use its custom kernel and libnvram. 
  cd firmadyne \
  See README in firmadyne and do as it says. \
  Here, we test DIR-815_FIRMWARE_1.01.ZIP, a router firmware image based on mipsel cpu arch. \
  Finally, we replace the run.sh in scratch/(num)/ with our modified one. \

##TriforceAFL: 
  run make \
  
##DECAF: upgraded to the newest qemu version 2.10.1
   It is included in qemu_mode/qemu dir. \
   If there is something wrong with sleuthkit, plese comment or not comment the following code. \
	LIBS="\$(SRC_PATH)/shared/sleuthkit/lib/libtsk.a -lbfd $LIBS" \

   In our case, run ./configure --target-list=mipsel-softmmu \
   run make \



