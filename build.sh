make clean all
cd llvm_mode
AFL_TRACE_PC=1 AFL_TRACE_IND=1 AFL_TRACE_CMP=1 AFL_TRACE_DIV=1 AFL_TRACE_GEP=1 AFL_TRACE_MEM=1 make clean all
cd ..
sudo AFL_TRACE_PC=1 make install
