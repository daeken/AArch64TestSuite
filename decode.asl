case (29 +: 3, 24 +: 5, 0 +: 24) of
	when (_, '0000x', _) =>
		case (29 +: 3, 25 +: 4, 16 +: 9, 0 +: 16) of
			when ('000', _, '000000000', _) => 
				__field imm16 0 +: 16
				case () of
					when () => __encoding aarch64_udf 
			when (_, _, !'000000000', _) => __UNPREDICTABLE
			when (!'000', _, _, _) => __UNPREDICTABLE
	when (_, '00011', _) => __UNPREDICTABLE
	when (_, '0010x', _) =>
		case (29 +: 3, 25 +: 4, 23 +: 2, 22 +: 1, 17 +: 5, 16 +: 1, 10 +: 6, 0 +: 10) of
			when ('000', _, '0x', _, '0xxxx', _, 'x1xxxx', _) =>
				case (24 +: 8, 22 +: 2, 21 +: 1, 16 +: 5, 15 +: 1, 14 +: 1, 0 +: 14) of
					when (_, _, _, _, '0', _, _) => 
						__field size 22 +: 2
						__field Zm 16 +: 5
						__field op 13 +: 1
						__field Pg 10 +: 3
						__field Zn 5 +: 5
						__field Zda 0 +: 5
						case (op) of
							when ('0') => __encoding MLA_Z_P_ZZZ__ 
							when ('1') => __encoding MLS_Z_P_ZZZ__ 
					when (_, _, _, _, '1', _, _) => 
						__field size 22 +: 2
						__field Zm 16 +: 5
						__field op 13 +: 1
						__field Pg 10 +: 3
						__field Za 5 +: 5
						__field Zdn 0 +: 5
						case (op) of
							when ('0') => __encoding MAD_Z_P_ZZZ__ 
							when ('1') => __encoding MSB_Z_P_ZZZ__ 
			when ('000', _, '0x', _, '0xxxx', _, '000xxx', _) =>
				case (24 +: 8, 22 +: 2, 21 +: 1, 18 +: 3, 16 +: 2, 13 +: 3, 0 +: 13) of
					when (_, _, _, '00x', _, _, _) => 
						__field size 22 +: 2
						__field opc 16 +: 3
						__field Pg 10 +: 3
						__field Zm 5 +: 5
						__field Zdn 0 +: 5
						case (opc) of
							when ('000') => __encoding ADD_Z_P_ZZ__ 
							when ('001') => __encoding SUB_Z_P_ZZ__ 
							when ('010') => __UNALLOCATED
							when ('011') => __encoding SUBR_Z_P_ZZ__ 
							when ('1xx') => __UNALLOCATED
					when (_, _, _, '01x', _, _, _) => 
						__field size 22 +: 2
						__field opc 17 +: 2
						__field U 16 +: 1
						__field Pg 10 +: 3
						__field Zm 5 +: 5
						__field Zdn 0 +: 5
						case (opc, U) of
							when ('00', '0') => __encoding SMAX_Z_P_ZZ__ 
							when ('00', '1') => __encoding UMAX_Z_P_ZZ__ 
							when ('01', '0') => __encoding SMIN_Z_P_ZZ__ 
							when ('01', '1') => __encoding UMIN_Z_P_ZZ__ 
							when ('10', '0') => __encoding SABD_Z_P_ZZ__ 
							when ('10', '1') => __encoding UABD_Z_P_ZZ__ 
							when ('11', _) => __UNALLOCATED
					when (_, _, _, '100', _, _, _) => 
						__field size 22 +: 2
						__field H 17 +: 1
						__field U 16 +: 1
						__field Pg 10 +: 3
						__field Zm 5 +: 5
						__field Zdn 0 +: 5
						case (H, U) of
							when ('0', '0') => __encoding MUL_Z_P_ZZ__ 
							when ('0', '1') => __UNALLOCATED
							when ('1', '0') => __encoding SMULH_Z_P_ZZ__ 
							when ('1', '1') => __encoding UMULH_Z_P_ZZ__ 
					when (_, _, _, '101', _, _, _) => 
						__field size 22 +: 2
						__field R 17 +: 1
						__field U 16 +: 1
						__field Pg 10 +: 3
						__field Zm 5 +: 5
						__field Zdn 0 +: 5
						case (R, U) of
							when ('0', '0') => __encoding SDIV_Z_P_ZZ__ 
							when ('0', '1') => __encoding UDIV_Z_P_ZZ__ 
							when ('1', '0') => __encoding SDIVR_Z_P_ZZ__ 
							when ('1', '1') => __encoding UDIVR_Z_P_ZZ__ 
					when (_, _, _, '11x', _, _, _) => 
						__field size 22 +: 2
						__field opc 16 +: 3
						__field Pg 10 +: 3
						__field Zm 5 +: 5
						__field Zdn 0 +: 5
						case (opc) of
							when ('000') => __encoding ORR_Z_P_ZZ__ 
							when ('001') => __encoding EOR_Z_P_ZZ__ 
							when ('010') => __encoding AND_Z_P_ZZ__ 
							when ('011') => __encoding BIC_Z_P_ZZ__ 
							when ('1xx') => __UNALLOCATED
			when ('000', _, '0x', _, '0xxxx', _, '001xxx', _) =>
				case (24 +: 8, 22 +: 2, 21 +: 1, 19 +: 2, 16 +: 3, 13 +: 3, 0 +: 13) of
					when (_, _, _, '00', _, _, _) => 
						__field size 22 +: 2
						__field opc 17 +: 2
						__field U 16 +: 1
						__field Pg 10 +: 3
						__field Zn 5 +: 5
						__field Vd 0 +: 5
						case (opc, U) of
							when ('00', '0') => __encoding SADDV_R_P_Z__ 
							when ('00', '1') => __encoding UADDV_R_P_Z__ 
							when ('01', _) => __UNALLOCATED
							when ('1x', _) => __UNALLOCATED
					when (_, _, _, '01', _, _, _) => 
						__field size 22 +: 2
						__field opc 17 +: 2
						__field U 16 +: 1
						__field Pg 10 +: 3
						__field Zn 5 +: 5
						__field Vd 0 +: 5
						case (opc, U) of
							when ('00', '0') => __encoding SMAXV_R_P_Z__ 
							when ('00', '1') => __encoding UMAXV_R_P_Z__ 
							when ('01', '0') => __encoding SMINV_R_P_Z__ 
							when ('01', '1') => __encoding UMINV_R_P_Z__ 
							when ('1x', _) => __UNALLOCATED
					when (_, _, _, '10', _, _, _) => 
						__field size 22 +: 2
						__field opc 17 +: 2
						__field M 16 +: 1
						__field Pg 10 +: 3
						__field Zn 5 +: 5
						__field Zd 0 +: 5
						case (opc) of
							when ('00') => __encoding MOVPRFX_Z_P_Z__ 
							when ('01') => __UNALLOCATED
							when ('1x') => __UNALLOCATED
					when (_, _, _, '11', _, _, _) => 
						__field size 22 +: 2
						__field opc 16 +: 3
						__field Pg 10 +: 3
						__field Zn 5 +: 5
						__field Vd 0 +: 5
						case (opc) of
							when ('000') => __encoding ORV_R_P_Z__ 
							when ('001') => __encoding EORV_R_P_Z__ 
							when ('010') => __encoding ANDV_R_P_Z__ 
							when ('011') => __UNALLOCATED
							when ('1xx') => __UNALLOCATED
			when ('000', _, '0x', _, '0xxxx', _, '100xxx', _) =>
				case (24 +: 8, 22 +: 2, 21 +: 1, 19 +: 2, 16 +: 3, 13 +: 3, 0 +: 13) of
					when (_, _, _, '0x', _, _, _) => 
						__field tszh 22 +: 2
						__field opc 18 +: 2
						__field L 17 +: 1
						__field U 16 +: 1
						__field Pg 10 +: 3
						__field tszl 8 +: 2
						__field imm3 5 +: 3
						__field Zdn 0 +: 5
						case (opc, L, U) of
							when ('00', '0', '0') => __encoding ASR_Z_P_ZI__ 
							when ('00', '0', '1') => __encoding LSR_Z_P_ZI__ 
							when ('00', '1', '0') => __UNALLOCATED
							when ('00', '1', '1') => __encoding LSL_Z_P_ZI__ 
							when ('01', '0', '0') => __encoding ASRD_Z_P_ZI__ 
							when ('01', '0', '1') => __UNALLOCATED
							when ('01', '1', _) => __UNALLOCATED
							when ('1x', _, _) => __UNALLOCATED
					when (_, _, _, '10', _, _, _) => 
						__field size 22 +: 2
						__field R 18 +: 1
						__field L 17 +: 1
						__field U 16 +: 1
						__field Pg 10 +: 3
						__field Zm 5 +: 5
						__field Zdn 0 +: 5
						case (R, L, U) of
							when (_, '1', '0') => __UNALLOCATED
							when ('0', '0', '0') => __encoding ASR_Z_P_ZZ__ 
							when ('0', '0', '1') => __encoding LSR_Z_P_ZZ__ 
							when ('0', '1', '1') => __encoding LSL_Z_P_ZZ__ 
							when ('1', '0', '0') => __encoding ASRR_Z_P_ZZ__ 
							when ('1', '0', '1') => __encoding LSRR_Z_P_ZZ__ 
							when ('1', '1', '1') => __encoding LSLR_Z_P_ZZ__ 
					when (_, _, _, '11', _, _, _) => 
						__field size 22 +: 2
						__field R 18 +: 1
						__field L 17 +: 1
						__field U 16 +: 1
						__field Pg 10 +: 3
						__field Zm 5 +: 5
						__field Zdn 0 +: 5
						case (R, L, U) of
							when ('0', '0', '0') => __encoding ASR_Z_P_ZW__ 
							when ('0', '0', '1') => __encoding LSR_Z_P_ZW__ 
							when ('0', '1', '0') => __UNALLOCATED
							when ('0', '1', '1') => __encoding LSL_Z_P_ZW__ 
							when ('1', _, _) => __UNALLOCATED
			when ('000', _, '0x', _, '0xxxx', _, '101xxx', _) =>
				case (24 +: 8, 22 +: 2, 21 +: 1, 19 +: 2, 16 +: 3, 13 +: 3, 0 +: 13) of
					when (_, _, _, '0x', _, _, _) => __UNPREDICTABLE
					when (_, _, _, '10', _, _, _) => 
						__field size 22 +: 2
						__field opc 16 +: 3
						__field Pg 10 +: 3
						__field Zn 5 +: 5
						__field Zd 0 +: 5
						case (opc) of
							when ('000') => __encoding SXTB_Z_P_Z__ 
							when ('001') => __encoding UXTB_Z_P_Z__ 
							when ('010') => __encoding SXTH_Z_P_Z__ 
							when ('011') => __encoding UXTH_Z_P_Z__ 
							when ('100') => __encoding SXTW_Z_P_Z__ 
							when ('101') => __encoding UXTW_Z_P_Z__ 
							when ('110') => __encoding ABS_Z_P_Z__ 
							when ('111') => __encoding NEG_Z_P_Z__ 
					when (_, _, _, '11', _, _, _) => 
						__field size 22 +: 2
						__field opc 16 +: 3
						__field Pg 10 +: 3
						__field Zn 5 +: 5
						__field Zd 0 +: 5
						case (opc) of
							when ('000') => __encoding CLS_Z_P_Z__ 
							when ('001') => __encoding CLZ_Z_P_Z__ 
							when ('010') => __encoding CNT_Z_P_Z__ 
							when ('011') => __encoding CNOT_Z_P_Z__ 
							when ('100') => __encoding FABS_Z_P_Z__ 
							when ('101') => __encoding FNEG_Z_P_Z__ 
							when ('110') => __encoding NOT_Z_P_Z__ 
							when ('111') => __UNALLOCATED
			when ('000', _, '0x', _, '1xxxx', _, '000xxx', _) => 
				__field size 22 +: 2
				__field Zm 16 +: 5
				__field opc 10 +: 3
				__field Zn 5 +: 5
				__field Zd 0 +: 5
				case (opc) of
					when ('000') => __encoding ADD_Z_ZZ__ 
					when ('001') => __encoding SUB_Z_ZZ__ 
					when ('01x') => __UNALLOCATED
					when ('100') => __encoding SQADD_Z_ZZ__ 
					when ('101') => __encoding UQADD_Z_ZZ__ 
					when ('110') => __encoding SQSUB_Z_ZZ__ 
					when ('111') => __encoding UQSUB_Z_ZZ__ 
			when ('000', _, '0x', _, '1xxxx', _, '001xxx', _) =>
				case (24 +: 8, 22 +: 2, 21 +: 1, 16 +: 5, 13 +: 3, 12 +: 1, 10 +: 2, 0 +: 10) of
					when (_, _, _, _, _, '0', _, _) => __UNPREDICTABLE
					when (_, _, _, _, _, '1', '00', _) => 
						__field opc 22 +: 2
						__field Zm 16 +: 5
						__field Zn 5 +: 5
						__field Zd 0 +: 5
						case (opc) of
							when ('00') => __encoding AND_Z_ZZ__ 
							when ('01') => __encoding ORR_Z_ZZ__ 
							when ('10') => __encoding EOR_Z_ZZ__ 
							when ('11') => __encoding BIC_Z_ZZ__ 
					when (_, _, _, _, _, '1', !'00', _) => __UNPREDICTABLE
			when ('000', _, '0x', _, '1xxxx', _, '0100xx', _) =>
				case (24 +: 8, 22 +: 2, 21 +: 1, 16 +: 5, 12 +: 4, 10 +: 2, 0 +: 10) of
					when (_, _, _, _, _, '00', _) => 
						__field size 22 +: 2
						__field imm5b 16 +: 5
						__field imm5 5 +: 5
						__field Zd 0 +: 5
						case () of
							when () => __encoding INDEX_Z_II__ 
					when (_, _, _, _, _, '01', _) => 
						__field size 22 +: 2
						__field imm5 16 +: 5
						__field Rn 5 +: 5
						__field Zd 0 +: 5
						case () of
							when () => __encoding INDEX_Z_RI__ 
					when (_, _, _, _, _, '10', _) => 
						__field size 22 +: 2
						__field Rm 16 +: 5
						__field imm5 5 +: 5
						__field Zd 0 +: 5
						case () of
							when () => __encoding INDEX_Z_IR__ 
					when (_, _, _, _, _, '11', _) => 
						__field size 22 +: 2
						__field Rm 16 +: 5
						__field Rn 5 +: 5
						__field Zd 0 +: 5
						case () of
							when () => __encoding INDEX_Z_RR__ 
			when ('000', _, '0x', _, '1xxxx', _, '0101xx', _) =>
				case (24 +: 8, 23 +: 1, 22 +: 1, 21 +: 1, 16 +: 5, 12 +: 4, 11 +: 1, 0 +: 11) of
					when (_, '0', _, _, _, _, '0', _) => 
						__field op 22 +: 1
						__field Rn 16 +: 5
						__field imm6 5 +: 6
						__field Rd 0 +: 5
						case (op) of
							when ('0') => __encoding ADDVL_R_RI__ 
							when ('1') => __encoding ADDPL_R_RI__ 
					when (_, '1', _, _, _, _, '0', _) => 
						__field op 22 +: 1
						__field opc2 16 +: 5
						__field imm6 5 +: 6
						__field Rd 0 +: 5
						case (op, opc2) of
							when ('0', '0xxxx') => __UNALLOCATED
							when ('0', '10xxx') => __UNALLOCATED
							when ('0', '110xx') => __UNALLOCATED
							when ('0', '1110x') => __UNALLOCATED
							when ('0', '11110') => __UNALLOCATED
							when ('0', '11111') => __encoding RDVL_R_I__ 
							when ('1', _) => __UNALLOCATED
					when (_, _, _, _, _, _, '1', _) => __UNPREDICTABLE
			when ('000', _, '0x', _, '1xxxx', _, '011xxx', _) => __UNPREDICTABLE
			when ('000', _, '0x', _, '1xxxx', _, '100xxx', _) =>
				case (24 +: 8, 22 +: 2, 21 +: 1, 16 +: 5, 13 +: 3, 12 +: 1, 0 +: 12) of
					when (_, _, _, _, _, '0', _) => 
						__field size 22 +: 2
						__field Zm 16 +: 5
						__field opc 10 +: 2
						__field Zn 5 +: 5
						__field Zd 0 +: 5
						case (opc) of
							when ('00') => __encoding ASR_Z_ZW__ 
							when ('01') => __encoding LSR_Z_ZW__ 
							when ('10') => __UNALLOCATED
							when ('11') => __encoding LSL_Z_ZW__ 
					when (_, _, _, _, _, '1', _) => 
						__field tszh 22 +: 2
						__field tszl 19 +: 2
						__field imm3 16 +: 3
						__field opc 10 +: 2
						__field Zn 5 +: 5
						__field Zd 0 +: 5
						case (opc) of
							when ('00') => __encoding ASR_Z_ZI__ 
							when ('01') => __encoding LSR_Z_ZI__ 
							when ('10') => __UNALLOCATED
							when ('11') => __encoding LSL_Z_ZI__ 
			when ('000', _, '0x', _, '1xxxx', _, '1010xx', _) => 
				__field opc 22 +: 2
				__field Zm 16 +: 5
				__field msz 10 +: 2
				__field Zn 5 +: 5
				__field Zd 0 +: 5
				case (opc) of
					when ('00') => __encoding ADR_Z_AZ_D_s32_scaled 
					when ('01') => __encoding ADR_Z_AZ_D_u32_scaled 
					when ('1x') => __encoding ADR_Z_AZ_SD_same_scaled 
			when ('000', _, '0x', _, '1xxxx', _, '1011xx', _) =>
				case (24 +: 8, 22 +: 2, 21 +: 1, 16 +: 5, 12 +: 4, 10 +: 2, 0 +: 10) of
					when (_, _, _, _, _, '0x', _) => 
						__field size 22 +: 2
						__field Zm 16 +: 5
						__field op 10 +: 1
						__field Zn 5 +: 5
						__field Zd 0 +: 5
						case (op) of
							when ('0') => __encoding FTSSEL_Z_ZZ__ 
							when ('1') => __UNALLOCATED
					when (_, _, _, _, _, '10', _) => 
						__field size 22 +: 2
						__field opc 16 +: 5
						__field Zn 5 +: 5
						__field Zd 0 +: 5
						case (opc) of
							when ('00000') => __encoding FEXPA_Z_Z__ 
							when ('00001') => __UNALLOCATED
							when ('0001x') => __UNALLOCATED
							when ('001xx') => __UNALLOCATED
							when ('01xxx') => __UNALLOCATED
							when ('1xxxx') => __UNALLOCATED
					when (_, _, _, _, _, '11', _) => 
						__field opc 22 +: 2
						__field opc2 16 +: 5
						__field Zn 5 +: 5
						__field Zd 0 +: 5
						case (opc, opc2) of
							when ('00', '00000') => __encoding MOVPRFX_Z_Z__ 
							when ('00', '00001') => __UNALLOCATED
							when ('00', '0001x') => __UNALLOCATED
							when ('00', '001xx') => __UNALLOCATED
							when ('00', '01xxx') => __UNALLOCATED
							when ('00', '1xxxx') => __UNALLOCATED
							when ('01', _) => __UNALLOCATED
							when ('1x', _) => __UNALLOCATED
			when ('000', _, '0x', _, '1xxxx', _, '11xxxx', _) =>
				case (24 +: 8, 22 +: 2, 21 +: 1, 20 +: 1, 16 +: 4, 14 +: 2, 11 +: 3, 0 +: 11) of
					when (_, _, _, '0', _, _, '00x', _) => 
						__field size 22 +: 2
						__field imm4 16 +: 4
						__field D 11 +: 1
						__field U 10 +: 1
						__field pattern 5 +: 5
						__field Zdn 0 +: 5
						case (size, D, U) of
							when ('00', _, _) => __UNALLOCATED
							when ('01', '0', '0') => __encoding SQINCH_Z_ZS__ 
							when ('01', '0', '1') => __encoding UQINCH_Z_ZS__ 
							when ('01', '1', '0') => __encoding SQDECH_Z_ZS__ 
							when ('01', '1', '1') => __encoding UQDECH_Z_ZS__ 
							when ('10', '0', '0') => __encoding SQINCW_Z_ZS__ 
							when ('10', '0', '1') => __encoding UQINCW_Z_ZS__ 
							when ('10', '1', '0') => __encoding SQDECW_Z_ZS__ 
							when ('10', '1', '1') => __encoding UQDECW_Z_ZS__ 
							when ('11', '0', '0') => __encoding SQINCD_Z_ZS__ 
							when ('11', '0', '1') => __encoding UQINCD_Z_ZS__ 
							when ('11', '1', '0') => __encoding SQDECD_Z_ZS__ 
							when ('11', '1', '1') => __encoding UQDECD_Z_ZS__ 
					when (_, _, _, '0', _, _, '100', _) => 
						__field size 22 +: 2
						__field imm4 16 +: 4
						__field op 10 +: 1
						__field pattern 5 +: 5
						__field Rd 0 +: 5
						case (size, op) of
							when (_, '1') => __UNALLOCATED
							when ('00', '0') => __encoding CNTB_R_S__ 
							when ('01', '0') => __encoding CNTH_R_S__ 
							when ('10', '0') => __encoding CNTW_R_S__ 
							when ('11', '0') => __encoding CNTD_R_S__ 
					when (_, _, _, '0', _, _, '101', _) => __UNPREDICTABLE
					when (_, _, _, '1', _, _, '000', _) => 
						__field size 22 +: 2
						__field imm4 16 +: 4
						__field D 10 +: 1
						__field pattern 5 +: 5
						__field Zdn 0 +: 5
						case (size, D) of
							when ('00', _) => __UNALLOCATED
							when ('01', '0') => __encoding INCH_Z_ZS__ 
							when ('01', '1') => __encoding DECH_Z_ZS__ 
							when ('10', '0') => __encoding INCW_Z_ZS__ 
							when ('10', '1') => __encoding DECW_Z_ZS__ 
							when ('11', '0') => __encoding INCD_Z_ZS__ 
							when ('11', '1') => __encoding DECD_Z_ZS__ 
					when (_, _, _, '1', _, _, '100', _) => 
						__field size 22 +: 2
						__field imm4 16 +: 4
						__field D 10 +: 1
						__field pattern 5 +: 5
						__field Rdn 0 +: 5
						case (size, D) of
							when ('00', '0') => __encoding INCB_R_RS__ 
							when ('00', '1') => __encoding DECB_R_RS__ 
							when ('01', '0') => __encoding INCH_R_RS__ 
							when ('01', '1') => __encoding DECH_R_RS__ 
							when ('10', '0') => __encoding INCW_R_RS__ 
							when ('10', '1') => __encoding DECW_R_RS__ 
							when ('11', '0') => __encoding INCD_R_RS__ 
							when ('11', '1') => __encoding DECD_R_RS__ 
					when (_, _, _, '1', _, _, 'x01', _) => __UNPREDICTABLE
					when (_, _, _, _, _, _, '01x', _) => __UNPREDICTABLE
					when (_, _, _, _, _, _, '11x', _) => 
						__field size 22 +: 2
						__field sf 20 +: 1
						__field imm4 16 +: 4
						__field D 11 +: 1
						__field U 10 +: 1
						__field pattern 5 +: 5
						__field Rdn 0 +: 5
						case (size, sf, D, U) of
							when ('00', '0', '0', '0') => __encoding SQINCB_R_RS_SX 
							when ('00', '0', '0', '1') => __encoding UQINCB_R_RS_UW 
							when ('00', '0', '1', '0') => __encoding SQDECB_R_RS_SX 
							when ('00', '0', '1', '1') => __encoding UQDECB_R_RS_UW 
							when ('00', '1', '0', '0') => __encoding SQINCB_R_RS_X 
							when ('00', '1', '0', '1') => __encoding UQINCB_R_RS_X 
							when ('00', '1', '1', '0') => __encoding SQDECB_R_RS_X 
							when ('00', '1', '1', '1') => __encoding UQDECB_R_RS_X 
							when ('01', '0', '0', '0') => __encoding SQINCH_R_RS_SX 
							when ('01', '0', '0', '1') => __encoding UQINCH_R_RS_UW 
							when ('01', '0', '1', '0') => __encoding SQDECH_R_RS_SX 
							when ('01', '0', '1', '1') => __encoding UQDECH_R_RS_UW 
							when ('01', '1', '0', '0') => __encoding SQINCH_R_RS_X 
							when ('01', '1', '0', '1') => __encoding UQINCH_R_RS_X 
							when ('01', '1', '1', '0') => __encoding SQDECH_R_RS_X 
							when ('01', '1', '1', '1') => __encoding UQDECH_R_RS_X 
							when ('10', '0', '0', '0') => __encoding SQINCW_R_RS_SX 
							when ('10', '0', '0', '1') => __encoding UQINCW_R_RS_UW 
							when ('10', '0', '1', '0') => __encoding SQDECW_R_RS_SX 
							when ('10', '0', '1', '1') => __encoding UQDECW_R_RS_UW 
							when ('10', '1', '0', '0') => __encoding SQINCW_R_RS_X 
							when ('10', '1', '0', '1') => __encoding UQINCW_R_RS_X 
							when ('10', '1', '1', '0') => __encoding SQDECW_R_RS_X 
							when ('10', '1', '1', '1') => __encoding UQDECW_R_RS_X 
							when ('11', '0', '0', '0') => __encoding SQINCD_R_RS_SX 
							when ('11', '0', '0', '1') => __encoding UQINCD_R_RS_UW 
							when ('11', '0', '1', '0') => __encoding SQDECD_R_RS_SX 
							when ('11', '0', '1', '1') => __encoding UQDECD_R_RS_UW 
							when ('11', '1', '0', '0') => __encoding SQINCD_R_RS_X 
							when ('11', '1', '0', '1') => __encoding UQINCD_R_RS_X 
							when ('11', '1', '1', '0') => __encoding SQDECD_R_RS_X 
							when ('11', '1', '1', '1') => __encoding UQDECD_R_RS_X 
			when ('000', _, '1x', _, '00xxx', _, _, _) =>
				case (24 +: 8, 22 +: 2, 20 +: 2, 18 +: 2, 0 +: 18) of
					when (_, '11', _, '00', _) => 
						__field imm13 5 +: 13
						__field Zd 0 +: 5
						case () of
							when () => __encoding DUPM_Z_I__ 
					when (_, !'11', _, '00', _) => 
						__field opc 22 +: 2
						__field imm13 5 +: 13
						__field Zdn 0 +: 5
						case (opc) of
							when ('00') => __encoding ORR_Z_ZI__ 
							when ('01') => __encoding EOR_Z_ZI__ 
							when ('10') => __encoding AND_Z_ZI__ 
					when (_, _, _, !'00', _) => __UNPREDICTABLE
			when ('000', _, '1x', _, '01xxx', _, _, _) =>
				case (24 +: 8, 22 +: 2, 20 +: 2, 16 +: 4, 13 +: 3, 0 +: 13) of
					when (_, _, _, _, '0xx', _) => 
						__field size 22 +: 2
						__field Pg 16 +: 4
						__field M 14 +: 1
						__field sh 13 +: 1
						__field imm8 5 +: 8
						__field Zd 0 +: 5
						case (M) of
							when ('0') => __encoding CPY_Z_O_I__ 
							when ('1') => __encoding CPY_Z_P_I__ 
					when (_, _, _, _, '10x', _) => __UNPREDICTABLE
					when (_, _, _, _, '110', _) => 
						__field size 22 +: 2
						__field Pg 16 +: 4
						__field imm8 5 +: 8
						__field Zd 0 +: 5
						case () of
							when () => __encoding FCPY_Z_P_I__ 
					when (_, _, _, _, '111', _) => __UNPREDICTABLE
			when ('000', _, '1x', _, '1xxxx', _, '001xxx', _) =>
				case (24 +: 8, 22 +: 2, 21 +: 1, 19 +: 2, 17 +: 2, 16 +: 1, 13 +: 3, 12 +: 1, 10 +: 2, 0 +: 10) of
					when (_, _, _, '00', '00', '0', _, '1', '10', _) => 
						__field size 22 +: 2
						__field Rn 5 +: 5
						__field Zd 0 +: 5
						case () of
							when () => __encoding DUP_Z_R__ 
					when (_, _, _, '00', '10', '0', _, '1', '10', _) => 
						__field size 22 +: 2
						__field Rm 5 +: 5
						__field Zdn 0 +: 5
						case () of
							when () => __encoding INSR_Z_R__ 
					when (_, _, _, '00', 'x0', '0', _, '0', '01', _) => __UNPREDICTABLE
					when (_, _, _, '00', 'x0', '0', _, '1', 'x1', _) => __UNPREDICTABLE
					when (_, _, _, '00', 'x1', _, _, '1', '1x', _) => __UNPREDICTABLE
					when (_, _, _, '00', 'x1', _, _, _, '01', _) => __UNPREDICTABLE
					when (_, _, _, '00', _, '1', _, '1', '1x', _) => __UNPREDICTABLE
					when (_, _, _, '00', _, '1', _, _, '01', _) => __UNPREDICTABLE
					when (_, _, _, '00', _, _, _, '0', '1x', _) => __UNPREDICTABLE
					when (_, _, _, '01', _, _, _, _, !'00', _) => __UNPREDICTABLE
					when (_, _, _, '10', '0x', _, _, '0', '01', _) => __UNPREDICTABLE
					when (_, _, _, '10', '0x', _, _, '1', '10', _) => 
						__field size 22 +: 2
						__field U 17 +: 1
						__field H 16 +: 1
						__field Zn 5 +: 5
						__field Zd 0 +: 5
						case (U, H) of
							when ('0', '0') => __encoding SUNPKLO_Z_Z__ 
							when ('0', '1') => __encoding SUNPKHI_Z_Z__ 
							when ('1', '0') => __encoding UUNPKLO_Z_Z__ 
							when ('1', '1') => __encoding UUNPKHI_Z_Z__ 
					when (_, _, _, '10', '0x', _, _, '1', 'x1', _) => __UNPREDICTABLE
					when (_, _, _, '10', '10', '0', _, '0', '01', _) => __UNPREDICTABLE
					when (_, _, _, '10', '10', '0', _, '1', '10', _) => 
						__field size 22 +: 2
						__field Vm 5 +: 5
						__field Zdn 0 +: 5
						case () of
							when () => __encoding INSR_Z_V__ 
					when (_, _, _, '10', '10', '0', _, '1', 'x1', _) => __UNPREDICTABLE
					when (_, _, _, '10', '11', _, _, '1', '1x', _) => __UNPREDICTABLE
					when (_, _, _, '10', '11', _, _, _, '01', _) => __UNPREDICTABLE
					when (_, _, _, '10', '1x', '1', _, '1', '1x', _) => __UNPREDICTABLE
					when (_, _, _, '10', '1x', '1', _, _, '01', _) => __UNPREDICTABLE
					when (_, _, _, '11', '00', '0', _, '0', '01', _) => __UNPREDICTABLE
					when (_, _, _, '11', '00', '0', _, '1', '10', _) => 
						__field size 22 +: 2
						__field Zn 5 +: 5
						__field Zd 0 +: 5
						case () of
							when () => __encoding REV_Z_Z__ 
					when (_, _, _, '11', '00', '0', _, '1', 'x1', _) => __UNPREDICTABLE
					when (_, _, _, '11', '0x', '1', _, '1', '1x', _) => __UNPREDICTABLE
					when (_, _, _, '11', '0x', '1', _, _, '01', _) => __UNPREDICTABLE
					when (_, _, _, '11', !'00', _, _, '1', '1x', _) => __UNPREDICTABLE
					when (_, _, _, '11', !'00', _, _, _, '01', _) => __UNPREDICTABLE
					when (_, _, _, '1x', _, _, _, '0', '1x', _) => __UNPREDICTABLE
					when (_, _, _, _, _, _, _, '0', '00', _) => 
						__field imm2 22 +: 2
						__field tsz 16 +: 5
						__field Zn 5 +: 5
						__field Zd 0 +: 5
						case () of
							when () => __encoding DUP_Z_Zi__ 
					when (_, _, _, _, _, _, _, '1', '00', _) => 
						__field size 22 +: 2
						__field Zm 16 +: 5
						__field Zn 5 +: 5
						__field Zd 0 +: 5
						case () of
							when () => __encoding TBL_Z_ZZ_1 
			when ('000', _, '1x', _, '1xxxx', _, '010xxx', _) =>
				case (24 +: 8, 22 +: 2, 21 +: 1, 16 +: 5, 13 +: 3, 9 +: 4, 5 +: 4, 4 +: 1, 0 +: 4) of
					when (_, '00', _, '1000x', _, '0000', _, '0', _) => 
						__field H 16 +: 1
						__field Pn 5 +: 4
						__field Pd 0 +: 4
						case (H) of
							when ('0') => __encoding PUNPKLO_P_P__ 
							when ('1') => __encoding PUNPKHI_P_P__ 
					when (_, '01', _, '1000x', _, '0000', _, '0', _) => __UNPREDICTABLE
					when (_, '10', _, '1000x', _, '0000', _, '0', _) => __UNPREDICTABLE
					when (_, '11', _, '1000x', _, '0000', _, '0', _) => __UNPREDICTABLE
					when (_, _, _, '0xxxx', _, 'xxx0', _, '0', _) => 
						__field size 22 +: 2
						__field Pm 16 +: 4
						__field opc 11 +: 2
						__field H 10 +: 1
						__field Pn 5 +: 4
						__field Pd 0 +: 4
						case (opc, H) of
							when ('00', '0') => __encoding ZIP1_P_PP__ 
							when ('00', '1') => __encoding ZIP2_P_PP__ 
							when ('01', '0') => __encoding UZP1_P_PP__ 
							when ('01', '1') => __encoding UZP2_P_PP__ 
							when ('10', '0') => __encoding TRN1_P_PP__ 
							when ('10', '1') => __encoding TRN2_P_PP__ 
							when ('11', _) => __UNALLOCATED
					when (_, _, _, '0xxxx', _, 'xxx1', _, '0', _) => __UNPREDICTABLE
					when (_, _, _, '10100', _, '0000', _, '0', _) => 
						__field size 22 +: 2
						__field Pn 5 +: 4
						__field Pd 0 +: 4
						case () of
							when () => __encoding REV_P_P__ 
					when (_, _, _, '10101', _, '0000', _, '0', _) => __UNPREDICTABLE
					when (_, _, _, '10x0x', _, '1000', _, '0', _) => __UNPREDICTABLE
					when (_, _, _, '10x0x', _, 'x100', _, '0', _) => __UNPREDICTABLE
					when (_, _, _, '10x0x', _, 'xx10', _, '0', _) => __UNPREDICTABLE
					when (_, _, _, '10x0x', _, 'xxx1', _, '0', _) => __UNPREDICTABLE
					when (_, _, _, '10x1x', _, _, _, '0', _) => __UNPREDICTABLE
					when (_, _, _, '11xxx', _, _, _, '0', _) => __UNPREDICTABLE
					when (_, _, _, _, _, _, _, '1', _) => __UNPREDICTABLE
			when ('000', _, '1x', _, '1xxxx', _, '011xxx', _) => 
				__field size 22 +: 2
				__field Zm 16 +: 5
				__field opc 10 +: 3
				__field Zn 5 +: 5
				__field Zd 0 +: 5
				case (opc) of
					when ('000') => __encoding ZIP1_Z_ZZ__ 
					when ('001') => __encoding ZIP2_Z_ZZ__ 
					when ('010') => __encoding UZP1_Z_ZZ__ 
					when ('011') => __encoding UZP2_Z_ZZ__ 
					when ('100') => __encoding TRN1_Z_ZZ__ 
					when ('101') => __encoding TRN2_Z_ZZ__ 
					when ('11x') => __UNALLOCATED
			when ('000', _, '1x', _, '1xxxx', _, '10xxxx', _) =>
				case (24 +: 8, 22 +: 2, 21 +: 1, 20 +: 1, 17 +: 3, 16 +: 1, 14 +: 2, 13 +: 1, 0 +: 13) of
					when (_, _, _, '0', '000', '0', _, '0', _) => 
						__field size 22 +: 2
						__field Pg 10 +: 3
						__field Vn 5 +: 5
						__field Zd 0 +: 5
						case () of
							when () => __encoding CPY_Z_P_V__ 
					when (_, _, _, '0', '000', '1', _, '0', _) => 
						__field size 22 +: 2
						__field Pg 10 +: 3
						__field Zn 5 +: 5
						__field Zd 0 +: 5
						case () of
							when () => __encoding COMPACT_Z_P_Z__ 
					when (_, _, _, '0', '000', _, _, '1', _) => 
						__field size 22 +: 2
						__field B 16 +: 1
						__field Pg 10 +: 3
						__field Zn 5 +: 5
						__field Rd 0 +: 5
						case (B) of
							when ('0') => __encoding LASTA_R_P_Z__ 
							when ('1') => __encoding LASTB_R_P_Z__ 
					when (_, _, _, '0', '001', _, _, '0', _) => 
						__field size 22 +: 2
						__field B 16 +: 1
						__field Pg 10 +: 3
						__field Zn 5 +: 5
						__field Vd 0 +: 5
						case (B) of
							when ('0') => __encoding LASTA_V_P_Z__ 
							when ('1') => __encoding LASTB_V_P_Z__ 
					when (_, _, _, '0', '01x', _, _, '0', _) => 
						__field size 22 +: 2
						__field opc 16 +: 2
						__field Pg 10 +: 3
						__field Zn 5 +: 5
						__field Zd 0 +: 5
						case (opc) of
							when ('00') => __encoding REVB_Z_Z__ 
							when ('01') => __encoding REVH_Z_Z__ 
							when ('10') => __encoding REVW_Z_Z__ 
							when ('11') => __encoding RBIT_Z_P_Z__ 
					when (_, _, _, '0', '01x', _, _, '1', _) => __UNPREDICTABLE
					when (_, _, _, '0', '100', '0', _, '1', _) => 
						__field size 22 +: 2
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zd 0 +: 5
						case () of
							when () => __encoding CPY_Z_P_R__ 
					when (_, _, _, '0', '100', '1', _, '1', _) => __UNPREDICTABLE
					when (_, _, _, '0', '100', _, _, '0', _) => 
						__field size 22 +: 2
						__field B 16 +: 1
						__field Pg 10 +: 3
						__field Zm 5 +: 5
						__field Zdn 0 +: 5
						case (B) of
							when ('0') => __encoding CLASTA_Z_P_ZZ__ 
							when ('1') => __encoding CLASTB_Z_P_ZZ__ 
					when (_, _, _, '0', '101', _, _, '0', _) => 
						__field size 22 +: 2
						__field B 16 +: 1
						__field Pg 10 +: 3
						__field Zm 5 +: 5
						__field Vdn 0 +: 5
						case (B) of
							when ('0') => __encoding CLASTA_V_P_Z__ 
							when ('1') => __encoding CLASTB_V_P_Z__ 
					when (_, _, _, '0', '110', '0', _, '0', _) => 
						__field size 22 +: 2
						__field Pg 10 +: 3
						__field Zm 5 +: 5
						__field Zdn 0 +: 5
						case () of
							when () => __encoding SPLICE_Z_P_ZZ_Des 
					when (_, _, _, '0', '110', '0', _, '1', _) => __UNPREDICTABLE
					when (_, _, _, '0', '110', '1', _, _, _) => __UNPREDICTABLE
					when (_, _, _, '0', '111', '0', _, _, _) => __UNPREDICTABLE
					when (_, _, _, '0', '111', '1', _, _, _) => __UNPREDICTABLE
					when (_, _, _, '0', 'x01', _, _, '1', _) => __UNPREDICTABLE
					when (_, _, _, '1', '000', _, _, '0', _) => __UNPREDICTABLE
					when (_, _, _, '1', '000', _, _, '1', _) => 
						__field size 22 +: 2
						__field B 16 +: 1
						__field Pg 10 +: 3
						__field Zm 5 +: 5
						__field Rdn 0 +: 5
						case (B) of
							when ('0') => __encoding CLASTA_R_P_Z__ 
							when ('1') => __encoding CLASTB_R_P_Z__ 
					when (_, _, _, '1', !'000', _, _, _, _) => __UNPREDICTABLE
			when ('000', _, '1x', _, '1xxxx', _, '11xxxx', _) => 
				__field size 22 +: 2
				__field Zm 16 +: 5
				__field Pg 10 +: 4
				__field Zn 5 +: 5
				__field Zd 0 +: 5
				case () of
					when () => __encoding SEL_Z_P_ZZ__ 
			when ('000', _, '10', _, '1xxxx', _, '000xxx', _) =>
				case (23 +: 9, 22 +: 1, 21 +: 1, 16 +: 5, 13 +: 3, 0 +: 13) of
					when (_, '0', _, _, _, _) => 
						__field imm8h 16 +: 5
						__field imm8l 10 +: 3
						__field Zm 5 +: 5
						__field Zdn 0 +: 5
						case () of
							when () => __encoding EXT_Z_ZI_Des 
					when (_, '1', _, _, _, _) => __UNPREDICTABLE
			when ('000', _, '11', _, '1xxxx', _, '000xxx', _) => 
				__field op 22 +: 1
				__field Zm 16 +: 5
				__field opc2 10 +: 3
				__field Zn 5 +: 5
				__field Zd 0 +: 5
				case (op, opc2) of
					when ('0', '000') => __encoding ZIP1_Z_ZZ_Q 
					when ('0', '001') => __encoding ZIP2_Z_ZZ_Q 
					when ('0', '010') => __encoding UZP1_Z_ZZ_Q 
					when ('0', '011') => __encoding UZP2_Z_ZZ_Q 
					when ('0', '10x') => __UNALLOCATED
					when ('0', '110') => __encoding TRN1_Z_ZZ_Q 
					when ('0', '111') => __encoding TRN2_Z_ZZ_Q 
					when ('1', _) => __UNALLOCATED
			when ('001', _, '0x', _, '0xxxx', _, _, _) =>
				case (24 +: 8, 22 +: 2, 21 +: 1, 15 +: 6, 14 +: 1, 0 +: 14) of
					when (_, _, _, _, '0', _) => 
						__field size 22 +: 2
						__field Zm 16 +: 5
						__field op 15 +: 1
						__field o2 13 +: 1
						__field Pg 10 +: 3
						__field Zn 5 +: 5
						__field ne 4 +: 1
						__field Pd 0 +: 4
						case (op, o2, ne) of
							when ('0', '0', '0') => __encoding CMPHS_P_P_ZZ__ 
							when ('0', '0', '1') => __encoding CMPHI_P_P_ZZ__ 
							when ('0', '1', '0') => __encoding CMPEQ_P_P_ZW__ 
							when ('0', '1', '1') => __encoding CMPNE_P_P_ZW__ 
							when ('1', '0', '0') => __encoding CMPGE_P_P_ZZ__ 
							when ('1', '0', '1') => __encoding CMPGT_P_P_ZZ__ 
							when ('1', '1', '0') => __encoding CMPEQ_P_P_ZZ__ 
							when ('1', '1', '1') => __encoding CMPNE_P_P_ZZ__ 
					when (_, _, _, _, '1', _) => 
						__field size 22 +: 2
						__field Zm 16 +: 5
						__field U 15 +: 1
						__field lt 13 +: 1
						__field Pg 10 +: 3
						__field Zn 5 +: 5
						__field ne 4 +: 1
						__field Pd 0 +: 4
						case (U, lt, ne) of
							when ('0', '0', '0') => __encoding CMPGE_P_P_ZW__ 
							when ('0', '0', '1') => __encoding CMPGT_P_P_ZW__ 
							when ('0', '1', '0') => __encoding CMPLT_P_P_ZW__ 
							when ('0', '1', '1') => __encoding CMPLE_P_P_ZW__ 
							when ('1', '0', '0') => __encoding CMPHS_P_P_ZW__ 
							when ('1', '0', '1') => __encoding CMPHI_P_P_ZW__ 
							when ('1', '1', '0') => __encoding CMPLO_P_P_ZW__ 
							when ('1', '1', '1') => __encoding CMPLS_P_P_ZW__ 
			when ('001', _, '0x', _, '1xxxx', _, _, _) => 
				__field size 22 +: 2
				__field imm7 14 +: 7
				__field lt 13 +: 1
				__field Pg 10 +: 3
				__field Zn 5 +: 5
				__field ne 4 +: 1
				__field Pd 0 +: 4
				case (lt, ne) of
					when ('0', '0') => __encoding CMPHS_P_P_ZI__ 
					when ('0', '1') => __encoding CMPHI_P_P_ZI__ 
					when ('1', '0') => __encoding CMPLO_P_P_ZI__ 
					when ('1', '1') => __encoding CMPLS_P_P_ZI__ 
			when ('001', _, '1x', _, '0xxxx', _, 'x0xxxx', _) => 
				__field size 22 +: 2
				__field imm5 16 +: 5
				__field op 15 +: 1
				__field o2 13 +: 1
				__field Pg 10 +: 3
				__field Zn 5 +: 5
				__field ne 4 +: 1
				__field Pd 0 +: 4
				case (op, o2, ne) of
					when ('0', '0', '0') => __encoding CMPGE_P_P_ZI__ 
					when ('0', '0', '1') => __encoding CMPGT_P_P_ZI__ 
					when ('0', '1', '0') => __encoding CMPLT_P_P_ZI__ 
					when ('0', '1', '1') => __encoding CMPLE_P_P_ZI__ 
					when ('1', '0', '0') => __encoding CMPEQ_P_P_ZI__ 
					when ('1', '0', '1') => __encoding CMPNE_P_P_ZI__ 
					when ('1', '1', _) => __UNALLOCATED
			when ('001', _, '1x', _, '00xxx', _, '01xxxx', _) => 
				__field op 23 +: 1
				__field S 22 +: 1
				__field Pm 16 +: 4
				__field Pg 10 +: 4
				__field o2 9 +: 1
				__field Pn 5 +: 4
				__field o3 4 +: 1
				__field Pd 0 +: 4
				case (op, S, o2, o3) of
					when ('0', '0', '0', '0') => __encoding AND_P_P_PP_Z 
					when ('0', '0', '0', '1') => __encoding BIC_P_P_PP_Z 
					when ('0', '0', '1', '0') => __encoding EOR_P_P_PP_Z 
					when ('0', '0', '1', '1') => __encoding SEL_P_P_PP__ 
					when ('0', '1', '0', '0') => __encoding ANDS_P_P_PP_Z 
					when ('0', '1', '0', '1') => __encoding BICS_P_P_PP_Z 
					when ('0', '1', '1', '0') => __encoding EORS_P_P_PP_Z 
					when ('0', '1', '1', '1') => __UNALLOCATED
					when ('1', '0', '0', '0') => __encoding ORR_P_P_PP_Z 
					when ('1', '0', '0', '1') => __encoding ORN_P_P_PP_Z 
					when ('1', '0', '1', '0') => __encoding NOR_P_P_PP_Z 
					when ('1', '0', '1', '1') => __encoding NAND_P_P_PP_Z 
					when ('1', '1', '0', '0') => __encoding ORRS_P_P_PP_Z 
					when ('1', '1', '0', '1') => __encoding ORNS_P_P_PP_Z 
					when ('1', '1', '1', '0') => __encoding NORS_P_P_PP_Z 
					when ('1', '1', '1', '1') => __encoding NANDS_P_P_PP_Z 
			when ('001', _, '1x', _, '00xxx', _, '11xxxx', _) =>
				case (24 +: 8, 22 +: 2, 20 +: 2, 16 +: 4, 14 +: 2, 10 +: 4, 9 +: 1, 0 +: 9) of
					when (_, _, _, _, _, _, '0', _) => 
						__field op 23 +: 1
						__field S 22 +: 1
						__field Pm 16 +: 4
						__field Pg 10 +: 4
						__field Pn 5 +: 4
						__field B 4 +: 1
						__field Pd 0 +: 4
						case (op, S, B) of
							when ('0', '0', '0') => __encoding BRKPA_P_P_PP__ 
							when ('0', '0', '1') => __encoding BRKPB_P_P_PP__ 
							when ('0', '1', '0') => __encoding BRKPAS_P_P_PP__ 
							when ('0', '1', '1') => __encoding BRKPBS_P_P_PP__ 
							when ('1', _, _) => __UNALLOCATED
					when (_, _, _, _, _, _, '1', _) => __UNPREDICTABLE
			when ('001', _, '1x', _, '01xxx', _, '01xxxx', _) =>
				case (24 +: 8, 23 +: 1, 22 +: 1, 20 +: 2, 16 +: 4, 14 +: 2, 10 +: 4, 9 +: 1, 5 +: 4, 4 +: 1, 0 +: 4) of
					when (_, '0', _, _, '1000', _, _, '0', _, '0', _) => 
						__field S 22 +: 1
						__field Pg 10 +: 4
						__field Pn 5 +: 4
						__field Pdm 0 +: 4
						case (S) of
							when ('0') => __encoding BRKN_P_P_PP__ 
							when ('1') => __encoding BRKNS_P_P_PP__ 
					when (_, '0', _, _, '1000', _, _, '0', _, '1', _) => __UNPREDICTABLE
					when (_, '0', _, _, 'x000', _, _, '1', _, _, _) => __UNPREDICTABLE
					when (_, '0', _, _, 'x1xx', _, _, _, _, _, _) => __UNPREDICTABLE
					when (_, '0', _, _, 'xx1x', _, _, _, _, _, _) => __UNPREDICTABLE
					when (_, '0', _, _, 'xxx1', _, _, _, _, _, _) => __UNPREDICTABLE
					when (_, '1', _, _, '0000', _, _, '1', _, _, _) => __UNPREDICTABLE
					when (_, '1', _, _, !'0000', _, _, _, _, _, _) => __UNPREDICTABLE
					when (_, _, _, _, '0000', _, _, '0', _, _, _) => 
						__field B 23 +: 1
						__field S 22 +: 1
						__field Pg 10 +: 4
						__field Pn 5 +: 4
						__field M 4 +: 1
						__field Pd 0 +: 4
						case (B, S, M) of
							when (_, '1', '1') => __UNALLOCATED
							when ('0', '0', _) => __encoding BRKA_P_P_P__ 
							when ('0', '1', '0') => __encoding BRKAS_P_P_P_Z 
							when ('1', '0', _) => __encoding BRKB_P_P_P__ 
							when ('1', '1', '0') => __encoding BRKBS_P_P_P_Z 
			when ('001', _, '1x', _, '01xxx', _, '11xxxx', _) =>
				case (24 +: 8, 22 +: 2, 20 +: 2, 16 +: 4, 14 +: 2, 11 +: 3, 9 +: 2, 5 +: 4, 4 +: 1, 0 +: 4) of
					when (_, _, _, '0000', _, _, 'x0', _, '0', _) => 
						__field op 23 +: 1
						__field S 22 +: 1
						__field Pg 10 +: 4
						__field Pn 5 +: 4
						__field opc2 0 +: 4
						case (op, S, opc2) of
							when ('0', '0', _) => __UNALLOCATED
							when ('0', '1', '0000') => __encoding PTEST__P_P__ 
							when ('0', '1', '0001') => __UNALLOCATED
							when ('0', '1', '001x') => __UNALLOCATED
							when ('0', '1', '01xx') => __UNALLOCATED
							when ('0', '1', '1xxx') => __UNALLOCATED
							when ('1', _, _) => __UNALLOCATED
					when (_, _, _, '0100', _, _, 'x0', _, '0', _) => __UNPREDICTABLE
					when (_, _, _, '0x10', _, _, 'x0', _, '0', _) => __UNPREDICTABLE
					when (_, _, _, '0xx1', _, _, 'x0', _, '0', _) => __UNPREDICTABLE
					when (_, _, _, '0xxx', _, _, 'x1', _, '0', _) => __UNPREDICTABLE
					when (_, _, _, '1000', _, '000', '00', _, '0', _) => 
						__field op 23 +: 1
						__field S 22 +: 1
						__field Pg 5 +: 4
						__field Pdn 0 +: 4
						case (op, S) of
							when ('0', '0') => __UNALLOCATED
							when ('0', '1') => __encoding PFIRST_P_P_P__ 
							when ('1', _) => __UNALLOCATED
					when (_, _, _, '1000', _, '000', !'00', _, '0', _) => __UNPREDICTABLE
					when (_, _, _, '1000', _, '100', '10', '0000', '0', _) => 
						__field op 23 +: 1
						__field S 22 +: 1
						__field Pd 0 +: 4
						case (op, S) of
							when ('0', '0') => __encoding PFALSE_P__ 
							when ('0', '1') => __UNALLOCATED
							when ('1', _) => __UNALLOCATED
					when (_, _, _, '1000', _, '100', '10', !'0000', '0', _) => __UNPREDICTABLE
					when (_, _, _, '1000', _, '110', '00', _, '0', _) => 
						__field op 23 +: 1
						__field S 22 +: 1
						__field Pg 5 +: 4
						__field Pd 0 +: 4
						case (op, S) of
							when ('0', '0') => __encoding RDFFR_P_P_F__ 
							when ('0', '1') => __encoding RDFFRS_P_P_F__ 
							when ('1', _) => __UNALLOCATED
					when (_, _, _, '1001', _, '000', '0x', _, '0', _) => __UNPREDICTABLE
					when (_, _, _, '1001', _, '000', '10', _, '0', _) => 
						__field size 22 +: 2
						__field Pg 5 +: 4
						__field Pdn 0 +: 4
						case () of
							when () => __encoding PNEXT_P_P_P__ 
					when (_, _, _, '1001', _, '000', '11', _, '0', _) => __UNPREDICTABLE
					when (_, _, _, '1001', _, '100', '10', _, '0', _) => __UNPREDICTABLE
					when (_, _, _, '1001', _, '110', '00', '0000', '0', _) => 
						__field op 23 +: 1
						__field S 22 +: 1
						__field Pd 0 +: 4
						case (op, S) of
							when ('0', '0') => __encoding RDFFR_P_F__ 
							when ('0', '1') => __UNALLOCATED
							when ('1', _) => __UNALLOCATED
					when (_, _, _, '1001', _, '110', '00', !'0000', '0', _) => __UNPREDICTABLE
					when (_, _, _, '100x', _, '010', _, _, '0', _) => __UNPREDICTABLE
					when (_, _, _, '100x', _, '100', '0x', _, '0', _) => 
						__field size 22 +: 2
						__field S 16 +: 1
						__field pattern 5 +: 5
						__field Pd 0 +: 4
						case (S) of
							when ('0') => __encoding PTRUE_P_S__ 
							when ('1') => __encoding PTRUES_P_S__ 
					when (_, _, _, '100x', _, '100', '11', _, '0', _) => __UNPREDICTABLE
					when (_, _, _, '100x', _, '110', !'00', _, '0', _) => __UNPREDICTABLE
					when (_, _, _, '100x', _, 'xx1', _, _, '0', _) => __UNPREDICTABLE
					when (_, _, _, '110x', _, _, _, _, '0', _) => __UNPREDICTABLE
					when (_, _, _, '1x1x', _, _, _, _, '0', _) => __UNPREDICTABLE
					when (_, _, _, _, _, _, _, _, '1', _) => __UNPREDICTABLE
			when ('001', _, '1x', _, '1xxxx', _, '00xxxx', _) =>
				case (24 +: 8, 22 +: 2, 21 +: 1, 16 +: 5, 14 +: 2, 13 +: 1, 10 +: 3, 4 +: 6, 0 +: 4) of
					when (_, _, _, _, _, '0', _, _, _) => 
						__field size 22 +: 2
						__field Rm 16 +: 5
						__field sf 12 +: 1
						__field U 11 +: 1
						__field lt 10 +: 1
						__field Rn 5 +: 5
						__field eq 4 +: 1
						__field Pd 0 +: 4
						case (U, lt, eq) of
							when (_, '0', _) => __UNALLOCATED
							when ('0', '1', '0') => __encoding WHILELT_P_P_RR__ 
							when ('0', '1', '1') => __encoding WHILELE_P_P_RR__ 
							when ('1', '1', '0') => __encoding WHILELO_P_P_RR__ 
							when ('1', '1', '1') => __encoding WHILELS_P_P_RR__ 
					when (_, _, _, _, _, '1', '000', _, '0000') => 
						__field op 23 +: 1
						__field sz 22 +: 1
						__field Rm 16 +: 5
						__field Rn 5 +: 5
						__field ne 4 +: 1
						case (op, ne) of
							when ('0', _) => __UNALLOCATED
							when ('1', '0') => __encoding CTERMEQ_RR__ 
							when ('1', '1') => __encoding CTERMNE_RR__ 
					when (_, _, _, _, _, '1', '000', _, !'0000') => __UNPREDICTABLE
					when (_, _, _, _, _, '1', !'000', _, _) => __UNPREDICTABLE
			when ('001', _, '1x', _, '1xxxx', _, '01xxxx', _) => __UNPREDICTABLE
			when ('001', _, '1x', _, '1xxxx', _, '11xxxx', _) =>
				case (24 +: 8, 22 +: 2, 21 +: 1, 19 +: 2, 17 +: 2, 16 +: 1, 14 +: 2, 0 +: 14) of
					when (_, _, _, '00', _, _, _, _) => 
						__field size 22 +: 2
						__field opc 16 +: 3
						__field sh 13 +: 1
						__field imm8 5 +: 8
						__field Zdn 0 +: 5
						case (opc) of
							when ('000') => __encoding ADD_Z_ZI__ 
							when ('001') => __encoding SUB_Z_ZI__ 
							when ('010') => __UNALLOCATED
							when ('011') => __encoding SUBR_Z_ZI__ 
							when ('100') => __encoding SQADD_Z_ZI__ 
							when ('101') => __encoding UQADD_Z_ZI__ 
							when ('110') => __encoding SQSUB_Z_ZI__ 
							when ('111') => __encoding UQSUB_Z_ZI__ 
					when (_, _, _, '01', _, _, _, _) => 
						__field size 22 +: 2
						__field opc 16 +: 3
						__field o2 13 +: 1
						__field imm8 5 +: 8
						__field Zdn 0 +: 5
						case (opc, o2) of
							when ('0xx', '1') => __UNALLOCATED
							when ('000', '0') => __encoding SMAX_Z_ZI__ 
							when ('001', '0') => __encoding UMAX_Z_ZI__ 
							when ('010', '0') => __encoding SMIN_Z_ZI__ 
							when ('011', '0') => __encoding UMIN_Z_ZI__ 
							when ('1xx', _) => __UNALLOCATED
					when (_, _, _, '10', _, _, _, _) => 
						__field size 22 +: 2
						__field opc 16 +: 3
						__field o2 13 +: 1
						__field imm8 5 +: 8
						__field Zdn 0 +: 5
						case (opc, o2) of
							when ('000', '0') => __encoding MUL_Z_ZI__ 
							when ('000', '1') => __UNALLOCATED
							when ('001', _) => __UNALLOCATED
							when ('01x', _) => __UNALLOCATED
							when ('1xx', _) => __UNALLOCATED
					when (_, _, _, '11', _, '0', _, _) => 
						__field size 22 +: 2
						__field opc 17 +: 2
						__field sh 13 +: 1
						__field imm8 5 +: 8
						__field Zd 0 +: 5
						case (opc) of
							when ('00') => __encoding DUP_Z_I__ 
							when ('01') => __UNALLOCATED
							when ('1x') => __UNALLOCATED
					when (_, _, _, '11', _, '1', _, _) => 
						__field size 22 +: 2
						__field opc 17 +: 2
						__field o2 13 +: 1
						__field imm8 5 +: 8
						__field Zd 0 +: 5
						case (opc, o2) of
							when ('00', '0') => __encoding FDUP_Z_I__ 
							when ('00', '1') => __UNALLOCATED
							when ('01', _) => __UNALLOCATED
							when ('1x', _) => __UNALLOCATED
			when ('001', _, '1x', _, '100xx', _, '10xxxx', _) => 
				__field size 22 +: 2
				__field opc 16 +: 3
				__field Pg 10 +: 4
				__field o2 9 +: 1
				__field Pn 5 +: 4
				__field Rd 0 +: 5
				case (opc, o2) of
					when ('000', '0') => __encoding CNTP_R_P_P__ 
					when ('000', '1') => __UNALLOCATED
					when ('001', _) => __UNALLOCATED
					when ('01x', _) => __UNALLOCATED
					when ('1xx', _) => __UNALLOCATED
			when ('001', _, '1x', _, '101xx', _, '1000xx', _) =>
				case (24 +: 8, 22 +: 2, 19 +: 3, 18 +: 1, 16 +: 2, 12 +: 4, 11 +: 1, 0 +: 11) of
					when (_, _, _, '0', _, _, '0', _) => 
						__field size 22 +: 2
						__field D 17 +: 1
						__field U 16 +: 1
						__field opc 9 +: 2
						__field Pm 5 +: 4
						__field Zdn 0 +: 5
						case (D, U, opc) of
							when (_, _, '01') => __UNALLOCATED
							when (_, _, '1x') => __UNALLOCATED
							when ('0', '0', '00') => __encoding SQINCP_Z_P_Z__ 
							when ('0', '1', '00') => __encoding UQINCP_Z_P_Z__ 
							when ('1', '0', '00') => __encoding SQDECP_Z_P_Z__ 
							when ('1', '1', '00') => __encoding UQDECP_Z_P_Z__ 
					when (_, _, _, '0', _, _, '1', _) => 
						__field size 22 +: 2
						__field D 17 +: 1
						__field U 16 +: 1
						__field sf 10 +: 1
						__field op 9 +: 1
						__field Pm 5 +: 4
						__field Rdn 0 +: 5
						case (D, U, sf, op) of
							when (_, _, _, '1') => __UNALLOCATED
							when ('0', '0', '0', '0') => __encoding SQINCP_R_P_R_SX 
							when ('0', '0', '1', '0') => __encoding SQINCP_R_P_R_X 
							when ('0', '1', '0', '0') => __encoding UQINCP_R_P_R_UW 
							when ('0', '1', '1', '0') => __encoding UQINCP_R_P_R_X 
							when ('1', '0', '0', '0') => __encoding SQDECP_R_P_R_SX 
							when ('1', '0', '1', '0') => __encoding SQDECP_R_P_R_X 
							when ('1', '1', '0', '0') => __encoding UQDECP_R_P_R_UW 
							when ('1', '1', '1', '0') => __encoding UQDECP_R_P_R_X 
					when (_, _, _, '1', _, _, '0', _) => 
						__field size 22 +: 2
						__field op 17 +: 1
						__field D 16 +: 1
						__field opc2 9 +: 2
						__field Pm 5 +: 4
						__field Zdn 0 +: 5
						case (op, D, opc2) of
							when ('0', _, '01') => __UNALLOCATED
							when ('0', _, '1x') => __UNALLOCATED
							when ('0', '0', '00') => __encoding INCP_Z_P_Z__ 
							when ('0', '1', '00') => __encoding DECP_Z_P_Z__ 
							when ('1', _, _) => __UNALLOCATED
					when (_, _, _, '1', _, _, '1', _) => 
						__field size 22 +: 2
						__field op 17 +: 1
						__field D 16 +: 1
						__field opc2 9 +: 2
						__field Pm 5 +: 4
						__field Rdn 0 +: 5
						case (op, D, opc2) of
							when ('0', _, '01') => __UNALLOCATED
							when ('0', _, '1x') => __UNALLOCATED
							when ('0', '0', '00') => __encoding INCP_R_P_R__ 
							when ('0', '1', '00') => __encoding DECP_R_P_R__ 
							when ('1', _, _) => __UNALLOCATED
			when ('001', _, '1x', _, '101xx', _, '1001xx', _) =>
				case (24 +: 8, 22 +: 2, 19 +: 3, 18 +: 1, 16 +: 2, 12 +: 4, 9 +: 3, 5 +: 4, 0 +: 5) of
					when (_, _, _, '0', '00', _, '000', _, '00000') => 
						__field opc 22 +: 2
						__field Pn 5 +: 4
						case (opc) of
							when ('00') => __encoding WRFFR_F_P__ 
							when ('01') => __UNALLOCATED
							when ('1x') => __UNALLOCATED
					when (_, _, _, '1', '00', _, '000', '0000', '00000') => 
						__field opc 22 +: 2
						case (opc) of
							when ('00') => __encoding SETFFR_F__ 
							when ('01') => __UNALLOCATED
							when ('1x') => __UNALLOCATED
					when (_, _, _, '1', '00', _, '000', '1xxx', '00000') => __UNPREDICTABLE
					when (_, _, _, '1', '00', _, '000', 'x1xx', '00000') => __UNPREDICTABLE
					when (_, _, _, '1', '00', _, '000', 'xx1x', '00000') => __UNPREDICTABLE
					when (_, _, _, '1', '00', _, '000', 'xxx1', '00000') => __UNPREDICTABLE
					when (_, _, _, _, '00', _, '000', _, !'00000') => __UNPREDICTABLE
					when (_, _, _, _, '00', _, !'000', _, _) => __UNPREDICTABLE
					when (_, _, _, _, !'00', _, _, _, _) => __UNPREDICTABLE
			when ('001', _, '1x', _, '101xx', _, '101xxx', _) => __UNPREDICTABLE
			when ('001', _, '1x', _, '11xxx', _, '10xxxx', _) => __UNPREDICTABLE
			when ('010', _, '0x', _, '0xxxx', _, '0xxxxx', _) =>
				case (24 +: 8, 22 +: 2, 21 +: 1, 16 +: 5, 15 +: 1, 14 +: 1, 11 +: 3, 10 +: 1, 0 +: 10) of
					when (_, _, _, _, _, '0', '000', _, _) => 
						__field size 22 +: 2
						__field Zm 16 +: 5
						__field U 10 +: 1
						__field Zn 5 +: 5
						__field Zda 0 +: 5
						case (U) of
							when ('0') => __encoding SDOT_Z_ZZZ__ 
							when ('1') => __encoding UDOT_Z_ZZZ__ 
					when (_, _, _, _, _, '0', !'000', _, _) => __UNPREDICTABLE
					when (_, _, _, _, _, '1', '0xx', _, _) => __UNPREDICTABLE
					when (_, _, _, _, _, '1', '10x', _, _) => __UNPREDICTABLE
					when (_, _, _, _, _, '1', '110', _, _) => __UNPREDICTABLE
					when (_, _, _, _, _, '1', '111', '0', _) => 
						__field size 22 +: 2
						__field Zm 16 +: 5
						__field Zn 5 +: 5
						__field Zda 0 +: 5
						case (size) of
							when ('0x') => __UNALLOCATED
							when ('10') => __encoding USDOT_Z_ZZZ_S 
							when ('11') => __UNALLOCATED
					when (_, _, _, _, _, '1', '111', '1', _) => __UNPREDICTABLE
			when ('010', _, '0x', _, '0xxxx', _, '1xxxxx', _) => __UNPREDICTABLE
			when ('010', _, '0x', _, '1xxxx', _, _, _) =>
				case (24 +: 8, 22 +: 2, 21 +: 1, 16 +: 5, 13 +: 3, 11 +: 2, 0 +: 11) of
					when (_, _, _, _, '000', '00', _) => 
						__field size 22 +: 2
						__field opc 16 +: 5
						__field U 10 +: 1
						__field Zn 5 +: 5
						__field Zda 0 +: 5
						case (size, U) of
							when ('0x', _) => __UNALLOCATED
							when ('10', '0') => __encoding SDOT_Z_ZZZi_S 
							when ('10', '1') => __encoding UDOT_Z_ZZZi_S 
							when ('11', '0') => __encoding SDOT_Z_ZZZi_D 
							when ('11', '1') => __encoding UDOT_Z_ZZZi_D 
					when (_, _, _, _, '000', '01', _) => __UNPREDICTABLE
					when (_, _, _, _, '000', '10', _) => __UNPREDICTABLE
					when (_, _, _, _, '000', '11', _) => 
						__field size 22 +: 2
						__field opc 16 +: 5
						__field U 10 +: 1
						__field Zn 5 +: 5
						__field Zda 0 +: 5
						case (size, U) of
							when ('0x', _) => __UNALLOCATED
							when ('10', '0') => __encoding USDOT_Z_ZZZi_S 
							when ('10', '1') => __encoding SUDOT_Z_ZZZi_S 
							when ('11', _) => __UNALLOCATED
					when (_, _, _, _, !'000', _, _) => __UNPREDICTABLE
			when ('010', _, '1x', _, '0xxxx', _, '0xxxxx', _) => __UNPREDICTABLE
			when ('010', _, '1x', _, '0xxxx', _, '10xxxx', _) =>
				case (24 +: 8, 22 +: 2, 21 +: 1, 16 +: 5, 14 +: 2, 10 +: 4, 0 +: 10) of
					when (_, _, _, _, _, '00xx', _) => __UNPREDICTABLE
					when (_, _, _, _, _, '010x', _) => __UNPREDICTABLE
					when (_, _, _, _, _, '0110', _) => 
						__field uns 22 +: 2
						__field Zm 16 +: 5
						__field Zn 5 +: 5
						__field Zd 0 +: 5
						case (uns) of
							when ('00') => __encoding SMMLA_Z_ZZZ__ 
							when ('01') => __UNALLOCATED
							when ('10') => __encoding USMMLA_Z_ZZZ__ 
							when ('11') => __encoding UMMLA_Z_ZZZ__ 
					when (_, _, _, _, _, '0111', _) => __UNPREDICTABLE
					when (_, _, _, _, _, '1xxx', _) => __UNPREDICTABLE
			when ('010', _, '1x', _, '0xxxx', _, '11xxxx', _) => __UNPREDICTABLE
			when ('010', _, '1x', _, '1xxxx', _, _, _) => __UNPREDICTABLE
			when ('011', _, '0x', _, '0xxxx', _, '0xxxxx', _) => 
				__field size 22 +: 2
				__field Zm 16 +: 5
				__field rot 13 +: 2
				__field Pg 10 +: 3
				__field Zn 5 +: 5
				__field Zda 0 +: 5
				case () of
					when () => __encoding FCMLA_Z_P_ZZZ__ 
			when ('011', _, '0x', _, '00x1x', _, '1xxxxx', _) => __UNPREDICTABLE
			when ('011', _, '0x', _, '00000', _, '100xxx', _) => 
				__field size 22 +: 2
				__field rot 16 +: 1
				__field Pg 10 +: 3
				__field Zm 5 +: 5
				__field Zdn 0 +: 5
				case () of
					when () => __encoding FCADD_Z_P_ZZ__ 
			when ('011', _, '0x', _, '00000', _, '101xxx', _) => __UNPREDICTABLE
			when ('011', _, '0x', _, '00000', _, '11xxxx', _) => __UNPREDICTABLE
			when ('011', _, '0x', _, '00001', _, '1xxxxx', _) => __UNPREDICTABLE
			when ('011', _, '0x', _, '0010x', _, '100xxx', _) => __UNPREDICTABLE
			when ('011', _, '0x', _, '0010x', _, '101xxx', _) => 
				__field opc 22 +: 2
				__field opc2 16 +: 2
				__field Pg 10 +: 3
				__field Zn 5 +: 5
				__field Zd 0 +: 5
				case (opc, opc2) of
					when ('0x', _) => __UNALLOCATED
					when ('10', '0x') => __UNALLOCATED
					when ('10', '10') => __encoding BFCVTNT_Z_P_Z_S2BF 
					when ('10', '11') => __UNALLOCATED
					when ('11', _) => __UNALLOCATED
			when ('011', _, '0x', _, '0010x', _, '11xxxx', _) => __UNPREDICTABLE
			when ('011', _, '0x', _, '01xxx', _, '1xxxxx', _) => __UNPREDICTABLE
			when ('011', _, '0x', _, '1xxxx', _, 'x0x01x', _) => __UNPREDICTABLE
			when ('011', _, '0x', _, '1xxxx', _, '00000x', _) => 
				__field size 22 +: 2
				__field opc 16 +: 5
				__field op 10 +: 1
				__field Zn 5 +: 5
				__field Zda 0 +: 5
				case (size, op) of
					when ('0x', '0') => __encoding FMLA_Z_ZZZi_H 
					when ('0x', '1') => __encoding FMLS_Z_ZZZi_H 
					when ('10', '0') => __encoding FMLA_Z_ZZZi_S 
					when ('10', '1') => __encoding FMLS_Z_ZZZi_S 
					when ('11', '0') => __encoding FMLA_Z_ZZZi_D 
					when ('11', '1') => __encoding FMLS_Z_ZZZi_D 
			when ('011', _, '0x', _, '1xxxx', _, '0001xx', _) => 
				__field size 22 +: 2
				__field opc 16 +: 5
				__field rot 10 +: 2
				__field Zn 5 +: 5
				__field Zda 0 +: 5
				case (size) of
					when ('0x') => __UNALLOCATED
					when ('10') => __encoding FCMLA_Z_ZZZi_H 
					when ('11') => __encoding FCMLA_Z_ZZZi_S 
			when ('011', _, '0x', _, '1xxxx', _, '001000', _) => 
				__field size 22 +: 2
				__field opc 16 +: 5
				__field Zn 5 +: 5
				__field Zd 0 +: 5
				case (size) of
					when ('0x') => __encoding FMUL_Z_ZZi_H 
					when ('10') => __encoding FMUL_Z_ZZi_S 
					when ('11') => __encoding FMUL_Z_ZZi_D 
			when ('011', _, '0x', _, '1xxxx', _, '001001', _) => __UNPREDICTABLE
			when ('011', _, '0x', _, '1xxxx', _, '0011xx', _) => __UNPREDICTABLE
			when ('011', _, '0x', _, '1xxxx', _, '01x0xx', _) =>
				case (24 +: 8, 23 +: 1, 22 +: 1, 21 +: 1, 16 +: 5, 14 +: 2, 13 +: 1, 12 +: 1, 10 +: 2, 0 +: 10) of
					when (_, '0', _, _, _, _, '0', _, '00', _) => 
						__field op 22 +: 1
						__field i2 19 +: 2
						__field Zm 16 +: 3
						__field Zn 5 +: 5
						__field Zda 0 +: 5
						case (op) of
							when ('0') => __UNALLOCATED
							when ('1') => __encoding BFDOT_Z_ZZZi__ 
					when (_, '0', _, _, _, _, '0', _, !'00', _) => __UNPREDICTABLE
					when (_, '0', _, _, _, _, '1', _, _, _) => __UNPREDICTABLE
					when (_, '1', _, _, _, _, _, _, _, _) => 
						__field o2 22 +: 1
						__field i3h 19 +: 2
						__field Zm 16 +: 3
						__field op 13 +: 1
						__field i3l 11 +: 1
						__field T 10 +: 1
						__field Zn 5 +: 5
						__field Zda 0 +: 5
						case (o2, op, T) of
							when ('0', _, _) => __UNALLOCATED
							when ('1', '0', '0') => __encoding BFMLALB_Z_ZZZi__ 
							when ('1', '0', '1') => __encoding BFMLALT_Z_ZZZi__ 
							when ('1', '1', _) => __UNALLOCATED
			when ('011', _, '0x', _, '1xxxx', _, '01x1xx', _) => __UNPREDICTABLE
			when ('011', _, '0x', _, '1xxxx', _, '10x00x', _) =>
				case (24 +: 8, 23 +: 1, 22 +: 1, 21 +: 1, 16 +: 5, 14 +: 2, 13 +: 1, 11 +: 2, 10 +: 1, 0 +: 10) of
					when (_, '0', _, _, _, _, '0', _, '0', _) => 
						__field op 22 +: 1
						__field Zm 16 +: 5
						__field Zn 5 +: 5
						__field Zda 0 +: 5
						case (op) of
							when ('0') => __UNALLOCATED
							when ('1') => __encoding BFDOT_Z_ZZZ__ 
					when (_, '0', _, _, _, _, '0', _, '1', _) => __UNPREDICTABLE
					when (_, '0', _, _, _, _, '1', _, _, _) => __UNPREDICTABLE
					when (_, '1', _, _, _, _, _, _, _, _) => 
						__field o2 22 +: 1
						__field Zm 16 +: 5
						__field op 13 +: 1
						__field T 10 +: 1
						__field Zn 5 +: 5
						__field Zda 0 +: 5
						case (o2, op, T) of
							when ('0', _, _) => __UNALLOCATED
							when ('1', '0', '0') => __encoding BFMLALB_Z_ZZZ__ 
							when ('1', '0', '1') => __encoding BFMLALT_Z_ZZZ__ 
							when ('1', '1', _) => __UNALLOCATED
			when ('011', _, '0x', _, '1xxxx', _, '10x1xx', _) => __UNPREDICTABLE
			when ('011', _, '0x', _, '1xxxx', _, '110xxx', _) => __UNPREDICTABLE
			when ('011', _, '0x', _, '1xxxx', _, '111000', _) => __UNPREDICTABLE
			when ('011', _, '0x', _, '1xxxx', _, '111001', _) => 
				__field opc 22 +: 2
				__field Zm 16 +: 5
				__field Zn 5 +: 5
				__field Zda 0 +: 5
				case (opc) of
					when ('00') => __UNALLOCATED
					when ('01') => __encoding BFMMLA_Z_ZZZ__ 
					when ('10') => __encoding FMMLA_Z_ZZZ_S 
					when ('11') => __encoding FMMLA_Z_ZZZ_D 
			when ('011', _, '0x', _, '1xxxx', _, '11101x', _) => __UNPREDICTABLE
			when ('011', _, '0x', _, '1xxxx', _, '1111xx', _) => __UNPREDICTABLE
			when ('011', _, '1x', _, '0xxxx', _, 'x1xxxx', _) => 
				__field size 22 +: 2
				__field Zm 16 +: 5
				__field op 15 +: 1
				__field o2 13 +: 1
				__field Pg 10 +: 3
				__field Zn 5 +: 5
				__field o3 4 +: 1
				__field Pd 0 +: 4
				case (op, o2, o3) of
					when ('0', '0', '0') => __encoding FCMGE_P_P_ZZ__ 
					when ('0', '0', '1') => __encoding FCMGT_P_P_ZZ__ 
					when ('0', '1', '0') => __encoding FCMEQ_P_P_ZZ__ 
					when ('0', '1', '1') => __encoding FCMNE_P_P_ZZ__ 
					when ('1', '0', '0') => __encoding FCMUO_P_P_ZZ__ 
					when ('1', '0', '1') => __encoding FACGE_P_P_ZZ__ 
					when ('1', '1', '0') => __UNALLOCATED
					when ('1', '1', '1') => __encoding FACGT_P_P_ZZ__ 
			when ('011', _, '1x', _, '0xxxx', _, '000xxx', _) => 
				__field size 22 +: 2
				__field Zm 16 +: 5
				__field opc 10 +: 3
				__field Zn 5 +: 5
				__field Zd 0 +: 5
				case (opc) of
					when ('000') => __encoding FADD_Z_ZZ__ 
					when ('001') => __encoding FSUB_Z_ZZ__ 
					when ('010') => __encoding FMUL_Z_ZZ__ 
					when ('011') => __encoding FTSMUL_Z_ZZ__ 
					when ('10x') => __UNALLOCATED
					when ('110') => __encoding FRECPS_Z_ZZ__ 
					when ('111') => __encoding FRSQRTS_Z_ZZ__ 
			when ('011', _, '1x', _, '0xxxx', _, '100xxx', _) =>
				case (24 +: 8, 22 +: 2, 21 +: 1, 19 +: 2, 16 +: 3, 13 +: 3, 10 +: 3, 6 +: 4, 0 +: 6) of
					when (_, _, _, '0x', _, _, _, _, _) => 
						__field size 22 +: 2
						__field opc 16 +: 4
						__field Pg 10 +: 3
						__field Zm 5 +: 5
						__field Zdn 0 +: 5
						case (opc) of
							when ('0000') => __encoding FADD_Z_P_ZZ__ 
							when ('0001') => __encoding FSUB_Z_P_ZZ__ 
							when ('0010') => __encoding FMUL_Z_P_ZZ__ 
							when ('0011') => __encoding FSUBR_Z_P_ZZ__ 
							when ('0100') => __encoding FMAXNM_Z_P_ZZ__ 
							when ('0101') => __encoding FMINNM_Z_P_ZZ__ 
							when ('0110') => __encoding FMAX_Z_P_ZZ__ 
							when ('0111') => __encoding FMIN_Z_P_ZZ__ 
							when ('1000') => __encoding FABD_Z_P_ZZ__ 
							when ('1001') => __encoding FSCALE_Z_P_ZZ__ 
							when ('1010') => __encoding FMULX_Z_P_ZZ__ 
							when ('1011') => __UNALLOCATED
							when ('1100') => __encoding FDIVR_Z_P_ZZ__ 
							when ('1101') => __encoding FDIV_Z_P_ZZ__ 
							when ('111x') => __UNALLOCATED
					when (_, _, _, '10', _, _, '000', _, _) => 
						__field size 22 +: 2
						__field imm3 16 +: 3
						__field Zm 5 +: 5
						__field Zdn 0 +: 5
						case () of
							when () => __encoding FTMAD_Z_ZZI__ 
					when (_, _, _, '10', _, _, !'000', _, _) => __UNPREDICTABLE
					when (_, _, _, '11', _, _, _, '0000', _) => 
						__field size 22 +: 2
						__field opc 16 +: 3
						__field Pg 10 +: 3
						__field i1 5 +: 1
						__field Zdn 0 +: 5
						case (opc) of
							when ('000') => __encoding FADD_Z_P_ZS__ 
							when ('001') => __encoding FSUB_Z_P_ZS__ 
							when ('010') => __encoding FMUL_Z_P_ZS__ 
							when ('011') => __encoding FSUBR_Z_P_ZS__ 
							when ('100') => __encoding FMAXNM_Z_P_ZS__ 
							when ('101') => __encoding FMINNM_Z_P_ZS__ 
							when ('110') => __encoding FMAX_Z_P_ZS__ 
							when ('111') => __encoding FMIN_Z_P_ZS__ 
					when (_, _, _, '11', _, _, _, !'0000', _) => __UNPREDICTABLE
			when ('011', _, '1x', _, '0xxxx', _, '101xxx', _) =>
				case (24 +: 8, 22 +: 2, 21 +: 1, 18 +: 3, 16 +: 2, 13 +: 3, 0 +: 13) of
					when (_, _, _, '00x', _, _, _) => 
						__field size 22 +: 2
						__field opc 16 +: 3
						__field Pg 10 +: 3
						__field Zn 5 +: 5
						__field Zd 0 +: 5
						case (opc) of
							when ('000') => __encoding FRINTN_Z_P_Z__ 
							when ('001') => __encoding FRINTP_Z_P_Z__ 
							when ('010') => __encoding FRINTM_Z_P_Z__ 
							when ('011') => __encoding FRINTZ_Z_P_Z__ 
							when ('100') => __encoding FRINTA_Z_P_Z__ 
							when ('101') => __UNALLOCATED
							when ('110') => __encoding FRINTX_Z_P_Z__ 
							when ('111') => __encoding FRINTI_Z_P_Z__ 
					when (_, _, _, '010', _, _, _) => 
						__field opc 22 +: 2
						__field opc2 16 +: 2
						__field Pg 10 +: 3
						__field Zn 5 +: 5
						__field Zd 0 +: 5
						case (opc, opc2) of
							when ('0x', _) => __UNALLOCATED
							when ('10', '00') => __encoding FCVT_Z_P_Z_S2H 
							when ('10', '01') => __encoding FCVT_Z_P_Z_H2S 
							when ('10', '10') => __encoding BFCVT_Z_P_Z_S2BF 
							when ('10', '11') => __UNALLOCATED
							when ('11', '00') => __encoding FCVT_Z_P_Z_D2H 
							when ('11', '01') => __encoding FCVT_Z_P_Z_H2D 
							when ('11', '10') => __encoding FCVT_Z_P_Z_D2S 
							when ('11', '11') => __encoding FCVT_Z_P_Z_S2D 
					when (_, _, _, '011', _, _, _) => 
						__field size 22 +: 2
						__field opc 16 +: 2
						__field Pg 10 +: 3
						__field Zn 5 +: 5
						__field Zd 0 +: 5
						case (opc) of
							when ('00') => __encoding FRECPX_Z_P_Z__ 
							when ('01') => __encoding FSQRT_Z_P_Z__ 
							when ('1x') => __UNALLOCATED
					when (_, _, _, '10x', _, _, _) => 
						__field opc 22 +: 2
						__field opc2 17 +: 2
						__field U 16 +: 1
						__field Pg 10 +: 3
						__field Zn 5 +: 5
						__field Zd 0 +: 5
						case (opc, opc2, U) of
							when ('00', _, _) => __UNALLOCATED
							when ('01', '00', _) => __UNALLOCATED
							when ('01', '01', '0') => __encoding SCVTF_Z_P_Z_H2FP16 
							when ('01', '01', '1') => __encoding UCVTF_Z_P_Z_H2FP16 
							when ('01', '10', '0') => __encoding SCVTF_Z_P_Z_W2FP16 
							when ('01', '10', '1') => __encoding UCVTF_Z_P_Z_W2FP16 
							when ('01', '11', '0') => __encoding SCVTF_Z_P_Z_X2FP16 
							when ('01', '11', '1') => __encoding UCVTF_Z_P_Z_X2FP16 
							when ('10', '0x', _) => __UNALLOCATED
							when ('10', '10', '0') => __encoding SCVTF_Z_P_Z_W2S 
							when ('10', '10', '1') => __encoding UCVTF_Z_P_Z_W2S 
							when ('10', '11', _) => __UNALLOCATED
							when ('11', '00', '0') => __encoding SCVTF_Z_P_Z_W2D 
							when ('11', '00', '1') => __encoding UCVTF_Z_P_Z_W2D 
							when ('11', '01', _) => __UNALLOCATED
							when ('11', '10', '0') => __encoding SCVTF_Z_P_Z_X2S 
							when ('11', '10', '1') => __encoding UCVTF_Z_P_Z_X2S 
							when ('11', '11', '0') => __encoding SCVTF_Z_P_Z_X2D 
							when ('11', '11', '1') => __encoding UCVTF_Z_P_Z_X2D 
					when (_, _, _, '11x', _, _, _) => 
						__field opc 22 +: 2
						__field opc2 17 +: 2
						__field U 16 +: 1
						__field Pg 10 +: 3
						__field Zn 5 +: 5
						__field Zd 0 +: 5
						case (opc, opc2, U) of
							when ('00', _, _) => __UNALLOCATED
							when ('01', '00', _) => __UNALLOCATED
							when ('01', '01', '0') => __encoding FCVTZS_Z_P_Z_FP162H 
							when ('01', '01', '1') => __encoding FCVTZU_Z_P_Z_FP162H 
							when ('01', '10', '0') => __encoding FCVTZS_Z_P_Z_FP162W 
							when ('01', '10', '1') => __encoding FCVTZU_Z_P_Z_FP162W 
							when ('01', '11', '0') => __encoding FCVTZS_Z_P_Z_FP162X 
							when ('01', '11', '1') => __encoding FCVTZU_Z_P_Z_FP162X 
							when ('10', '0x', _) => __UNALLOCATED
							when ('10', '10', '0') => __encoding FCVTZS_Z_P_Z_S2W 
							when ('10', '10', '1') => __encoding FCVTZU_Z_P_Z_S2W 
							when ('10', '11', _) => __UNALLOCATED
							when ('11', '00', '0') => __encoding FCVTZS_Z_P_Z_D2W 
							when ('11', '00', '1') => __encoding FCVTZU_Z_P_Z_D2W 
							when ('11', '01', _) => __UNALLOCATED
							when ('11', '10', '0') => __encoding FCVTZS_Z_P_Z_S2X 
							when ('11', '10', '1') => __encoding FCVTZU_Z_P_Z_S2X 
							when ('11', '11', '0') => __encoding FCVTZS_Z_P_Z_D2X 
							when ('11', '11', '1') => __encoding FCVTZU_Z_P_Z_D2X 
			when ('011', _, '1x', _, '000xx', _, '001xxx', _) => 
				__field size 22 +: 2
				__field opc 16 +: 3
				__field Pg 10 +: 3
				__field Zn 5 +: 5
				__field Vd 0 +: 5
				case (opc) of
					when ('000') => __encoding FADDV_V_P_Z__ 
					when ('001') => __UNALLOCATED
					when ('01x') => __UNALLOCATED
					when ('100') => __encoding FMAXNMV_V_P_Z__ 
					when ('101') => __encoding FMINNMV_V_P_Z__ 
					when ('110') => __encoding FMAXV_V_P_Z__ 
					when ('111') => __encoding FMINV_V_P_Z__ 
			when ('011', _, '1x', _, '001xx', _, '0010xx', _) => __UNPREDICTABLE
			when ('011', _, '1x', _, '001xx', _, '0011xx', _) =>
				case (24 +: 8, 22 +: 2, 19 +: 3, 16 +: 3, 12 +: 4, 10 +: 2, 0 +: 10) of
					when (_, _, _, _, _, '00', _) => 
						__field size 22 +: 2
						__field opc 16 +: 3
						__field Zn 5 +: 5
						__field Zd 0 +: 5
						case (opc) of
							when ('0xx') => __UNALLOCATED
							when ('10x') => __UNALLOCATED
							when ('110') => __encoding FRECPE_Z_Z__ 
							when ('111') => __encoding FRSQRTE_Z_Z__ 
					when (_, _, _, _, _, !'00', _) => __UNPREDICTABLE
			when ('011', _, '1x', _, '010xx', _, '001xxx', _) =>
				case (24 +: 8, 22 +: 2, 19 +: 3, 18 +: 1, 16 +: 2, 13 +: 3, 0 +: 13) of
					when (_, _, _, '0', _, _, _) => 
						__field size 22 +: 2
						__field eq 17 +: 1
						__field lt 16 +: 1
						__field Pg 10 +: 3
						__field Zn 5 +: 5
						__field ne 4 +: 1
						__field Pd 0 +: 4
						case (eq, lt, ne) of
							when ('0', '0', '0') => __encoding FCMGE_P_P_Z0__ 
							when ('0', '0', '1') => __encoding FCMGT_P_P_Z0__ 
							when ('0', '1', '0') => __encoding FCMLT_P_P_Z0__ 
							when ('0', '1', '1') => __encoding FCMLE_P_P_Z0__ 
							when ('1', _, '1') => __UNALLOCATED
							when ('1', '0', '0') => __encoding FCMEQ_P_P_Z0__ 
							when ('1', '1', '0') => __encoding FCMNE_P_P_Z0__ 
					when (_, _, _, '1', _, _, _) => __UNPREDICTABLE
			when ('011', _, '1x', _, '011xx', _, '001xxx', _) => 
				__field size 22 +: 2
				__field opc 16 +: 3
				__field Pg 10 +: 3
				__field Zm 5 +: 5
				__field Vdn 0 +: 5
				case (opc) of
					when ('000') => __encoding FADDA_V_P_Z__ 
					when ('001') => __UNALLOCATED
					when ('01x') => __UNALLOCATED
					when ('1xx') => __UNALLOCATED
			when ('011', _, '1x', _, '1xxxx', _, _, _) =>
				case (24 +: 8, 22 +: 2, 21 +: 1, 16 +: 5, 15 +: 1, 0 +: 15) of
					when (_, _, _, _, '0', _) => 
						__field size 22 +: 2
						__field Zm 16 +: 5
						__field opc 13 +: 2
						__field Pg 10 +: 3
						__field Zn 5 +: 5
						__field Zda 0 +: 5
						case (opc) of
							when ('00') => __encoding FMLA_Z_P_ZZZ__ 
							when ('01') => __encoding FMLS_Z_P_ZZZ__ 
							when ('10') => __encoding FNMLA_Z_P_ZZZ__ 
							when ('11') => __encoding FNMLS_Z_P_ZZZ__ 
					when (_, _, _, _, '1', _) => 
						__field size 22 +: 2
						__field Za 16 +: 5
						__field opc 13 +: 2
						__field Pg 10 +: 3
						__field Zm 5 +: 5
						__field Zdn 0 +: 5
						case (opc) of
							when ('00') => __encoding FMAD_Z_P_ZZZ__ 
							when ('01') => __encoding FMSB_Z_P_ZZZ__ 
							when ('10') => __encoding FNMAD_Z_P_ZZZ__ 
							when ('11') => __encoding FNMSB_Z_P_ZZZ__ 
			when ('100', _, _, _, _, _, _, _) =>
				case (25 +: 7, 23 +: 2, 21 +: 2, 16 +: 5, 13 +: 3, 5 +: 8, 4 +: 1, 0 +: 4) of
					when (_, '00', 'x1', _, '0xx', _, '0', _) => 
						__field xs 22 +: 1
						__field Zm 16 +: 5
						__field msz 13 +: 2
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field prfop 0 +: 4
						case (msz) of
							when ('00') => __encoding PRFB_I_P_BZ_S_x32_scaled 
							when ('01') => __encoding PRFH_I_P_BZ_S_x32_scaled 
							when ('10') => __encoding PRFW_I_P_BZ_S_x32_scaled 
							when ('11') => __encoding PRFD_I_P_BZ_S_x32_scaled 
					when (_, '00', 'x1', _, '0xx', _, '1', _) => __UNPREDICTABLE
					when (_, '01', 'x1', _, '0xx', _, _, _) => 
						__field xs 22 +: 1
						__field Zm 16 +: 5
						__field U 14 +: 1
						__field ff 13 +: 1
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (U, ff) of
							when ('0', '0') => __encoding LD1SH_Z_P_BZ_S_x32_scaled 
							when ('0', '1') => __encoding LDFF1SH_Z_P_BZ_S_x32_scaled 
							when ('1', '0') => __encoding LD1H_Z_P_BZ_S_x32_scaled 
							when ('1', '1') => __encoding LDFF1H_Z_P_BZ_S_x32_scaled 
					when (_, '10', 'x1', _, '0xx', _, _, _) => 
						__field xs 22 +: 1
						__field Zm 16 +: 5
						__field U 14 +: 1
						__field ff 13 +: 1
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (U, ff) of
							when ('0', _) => __UNALLOCATED
							when ('1', '0') => __encoding LD1W_Z_P_BZ_S_x32_scaled 
							when ('1', '1') => __encoding LDFF1W_Z_P_BZ_S_x32_scaled 
					when (_, '11', '0x', _, '000', _, '0', _) => 
						__field imm9h 16 +: 6
						__field imm9l 10 +: 3
						__field Rn 5 +: 5
						__field Pt 0 +: 4
						case () of
							when () => __encoding LDR_P_BI__ 
					when (_, '11', '0x', _, '000', _, '1', _) => __UNPREDICTABLE
					when (_, '11', '0x', _, '010', _, _, _) => 
						__field imm9h 16 +: 6
						__field imm9l 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case () of
							when () => __encoding LDR_Z_BI__ 
					when (_, '11', '0x', _, '0x1', _, _, _) => __UNPREDICTABLE
					when (_, '11', '1x', _, '0xx', _, '0', _) => 
						__field imm6 16 +: 6
						__field msz 13 +: 2
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field prfop 0 +: 4
						case (msz) of
							when ('00') => __encoding PRFB_I_P_BI_S 
							when ('01') => __encoding PRFH_I_P_BI_S 
							when ('10') => __encoding PRFW_I_P_BI_S 
							when ('11') => __encoding PRFD_I_P_BI_S 
					when (_, '11', '1x', _, '0xx', _, '1', _) => __UNPREDICTABLE
					when (_, !'11', 'x0', _, '0xx', _, _, _) => 
						__field opc 23 +: 2
						__field xs 22 +: 1
						__field Zm 16 +: 5
						__field U 14 +: 1
						__field ff 13 +: 1
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (opc, U, ff) of
							when ('00', '0', '0') => __encoding LD1SB_Z_P_BZ_S_x32_unscaled 
							when ('00', '0', '1') => __encoding LDFF1SB_Z_P_BZ_S_x32_unscaled 
							when ('00', '1', '0') => __encoding LD1B_Z_P_BZ_S_x32_unscaled 
							when ('00', '1', '1') => __encoding LDFF1B_Z_P_BZ_S_x32_unscaled 
							when ('01', '0', '0') => __encoding LD1SH_Z_P_BZ_S_x32_unscaled 
							when ('01', '0', '1') => __encoding LDFF1SH_Z_P_BZ_S_x32_unscaled 
							when ('01', '1', '0') => __encoding LD1H_Z_P_BZ_S_x32_unscaled 
							when ('01', '1', '1') => __encoding LDFF1H_Z_P_BZ_S_x32_unscaled 
							when ('10', '0', _) => __UNALLOCATED
							when ('10', '1', '0') => __encoding LD1W_Z_P_BZ_S_x32_unscaled 
							when ('10', '1', '1') => __encoding LDFF1W_Z_P_BZ_S_x32_unscaled 
					when (_, _, '00', _, '10x', _, _, _) => __UNPREDICTABLE
					when (_, _, '00', _, '110', _, '0', _) => 
						__field msz 23 +: 2
						__field Rm 16 +: 5
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field prfop 0 +: 4
						case (msz) of
							when ('00') => __encoding PRFB_I_P_BR_S 
							when ('01') => __encoding PRFH_I_P_BR_S 
							when ('10') => __encoding PRFW_I_P_BR_S 
							when ('11') => __encoding PRFD_I_P_BR_S 
					when (_, _, '00', _, '111', _, '0', _) => 
						__field msz 23 +: 2
						__field imm5 16 +: 5
						__field Pg 10 +: 3
						__field Zn 5 +: 5
						__field prfop 0 +: 4
						case (msz) of
							when ('00') => __encoding PRFB_I_P_AI_S 
							when ('01') => __encoding PRFH_I_P_AI_S 
							when ('10') => __encoding PRFW_I_P_AI_S 
							when ('11') => __encoding PRFD_I_P_AI_S 
					when (_, _, '00', _, '11x', _, '1', _) => __UNPREDICTABLE
					when (_, _, '01', _, '1xx', _, _, _) => 
						__field msz 23 +: 2
						__field imm5 16 +: 5
						__field U 14 +: 1
						__field ff 13 +: 1
						__field Pg 10 +: 3
						__field Zn 5 +: 5
						__field Zt 0 +: 5
						case (msz, U, ff) of
							when ('00', '0', '0') => __encoding LD1SB_Z_P_AI_S 
							when ('00', '0', '1') => __encoding LDFF1SB_Z_P_AI_S 
							when ('00', '1', '0') => __encoding LD1B_Z_P_AI_S 
							when ('00', '1', '1') => __encoding LDFF1B_Z_P_AI_S 
							when ('01', '0', '0') => __encoding LD1SH_Z_P_AI_S 
							when ('01', '0', '1') => __encoding LDFF1SH_Z_P_AI_S 
							when ('01', '1', '0') => __encoding LD1H_Z_P_AI_S 
							when ('01', '1', '1') => __encoding LDFF1H_Z_P_AI_S 
							when ('10', '0', _) => __UNALLOCATED
							when ('10', '1', '0') => __encoding LD1W_Z_P_AI_S 
							when ('10', '1', '1') => __encoding LDFF1W_Z_P_AI_S 
							when ('11', _, _) => __UNALLOCATED
					when (_, _, '1x', _, '1xx', _, _, _) => 
						__field dtypeh 23 +: 2
						__field imm6 16 +: 6
						__field dtypel 13 +: 2
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (dtypeh, dtypel) of
							when ('00', '00') => __encoding LD1RB_Z_P_BI_U8 
							when ('00', '01') => __encoding LD1RB_Z_P_BI_U16 
							when ('00', '10') => __encoding LD1RB_Z_P_BI_U32 
							when ('00', '11') => __encoding LD1RB_Z_P_BI_U64 
							when ('01', '00') => __encoding LD1RSW_Z_P_BI_S64 
							when ('01', '01') => __encoding LD1RH_Z_P_BI_U16 
							when ('01', '10') => __encoding LD1RH_Z_P_BI_U32 
							when ('01', '11') => __encoding LD1RH_Z_P_BI_U64 
							when ('10', '00') => __encoding LD1RSH_Z_P_BI_S64 
							when ('10', '01') => __encoding LD1RSH_Z_P_BI_S32 
							when ('10', '10') => __encoding LD1RW_Z_P_BI_U32 
							when ('10', '11') => __encoding LD1RW_Z_P_BI_U64 
							when ('11', '00') => __encoding LD1RSB_Z_P_BI_S64 
							when ('11', '01') => __encoding LD1RSB_Z_P_BI_S32 
							when ('11', '10') => __encoding LD1RSB_Z_P_BI_S16 
							when ('11', '11') => __encoding LD1RD_Z_P_BI_U64 
			when ('101', _, _, _, _, _, _, _) =>
				case (25 +: 7, 23 +: 2, 21 +: 2, 20 +: 1, 16 +: 4, 13 +: 3, 0 +: 13) of
					when (_, _, '00', '0', _, '111', _) => 
						__field msz 23 +: 2
						__field imm4 16 +: 4
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (msz) of
							when ('00') => __encoding LDNT1B_Z_P_BI_Contiguous 
							when ('01') => __encoding LDNT1H_Z_P_BI_Contiguous 
							when ('10') => __encoding LDNT1W_Z_P_BI_Contiguous 
							when ('11') => __encoding LDNT1D_Z_P_BI_Contiguous 
					when (_, _, '00', _, _, '110', _) => 
						__field msz 23 +: 2
						__field Rm 16 +: 5
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (msz) of
							when ('00') => __encoding LDNT1B_Z_P_BR_Contiguous 
							when ('01') => __encoding LDNT1H_Z_P_BR_Contiguous 
							when ('10') => __encoding LDNT1W_Z_P_BR_Contiguous 
							when ('11') => __encoding LDNT1D_Z_P_BR_Contiguous 
					when (_, _, !'00', '0', _, '111', _) => 
						__field msz 23 +: 2
						__field opc 21 +: 2
						__field imm4 16 +: 4
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (msz, opc) of
							when ('00', '01') => __encoding LD2B_Z_P_BI_Contiguous 
							when ('00', '10') => __encoding LD3B_Z_P_BI_Contiguous 
							when ('00', '11') => __encoding LD4B_Z_P_BI_Contiguous 
							when ('01', '01') => __encoding LD2H_Z_P_BI_Contiguous 
							when ('01', '10') => __encoding LD3H_Z_P_BI_Contiguous 
							when ('01', '11') => __encoding LD4H_Z_P_BI_Contiguous 
							when ('10', '01') => __encoding LD2W_Z_P_BI_Contiguous 
							when ('10', '10') => __encoding LD3W_Z_P_BI_Contiguous 
							when ('10', '11') => __encoding LD4W_Z_P_BI_Contiguous 
							when ('11', '01') => __encoding LD2D_Z_P_BI_Contiguous 
							when ('11', '10') => __encoding LD3D_Z_P_BI_Contiguous 
							when ('11', '11') => __encoding LD4D_Z_P_BI_Contiguous 
					when (_, _, !'00', _, _, '110', _) => 
						__field msz 23 +: 2
						__field opc 21 +: 2
						__field Rm 16 +: 5
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (msz, opc) of
							when ('00', '01') => __encoding LD2B_Z_P_BR_Contiguous 
							when ('00', '10') => __encoding LD3B_Z_P_BR_Contiguous 
							when ('00', '11') => __encoding LD4B_Z_P_BR_Contiguous 
							when ('01', '01') => __encoding LD2H_Z_P_BR_Contiguous 
							when ('01', '10') => __encoding LD3H_Z_P_BR_Contiguous 
							when ('01', '11') => __encoding LD4H_Z_P_BR_Contiguous 
							when ('10', '01') => __encoding LD2W_Z_P_BR_Contiguous 
							when ('10', '10') => __encoding LD3W_Z_P_BR_Contiguous 
							when ('10', '11') => __encoding LD4W_Z_P_BR_Contiguous 
							when ('11', '01') => __encoding LD2D_Z_P_BR_Contiguous 
							when ('11', '10') => __encoding LD3D_Z_P_BR_Contiguous 
							when ('11', '11') => __encoding LD4D_Z_P_BR_Contiguous 
					when (_, _, _, '0', _, '001', _) => 
						__field msz 23 +: 2
						__field ssz 21 +: 2
						__field imm4 16 +: 4
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (msz, ssz) of
							when (_, '1x') => __UNALLOCATED
							when ('00', '00') => __encoding LD1RQB_Z_P_BI_U8 
							when ('00', '01') => __encoding LD1ROB_Z_P_BI_U8 
							when ('01', '00') => __encoding LD1RQH_Z_P_BI_U16 
							when ('01', '01') => __encoding LD1ROH_Z_P_BI_U16 
							when ('10', '00') => __encoding LD1RQW_Z_P_BI_U32 
							when ('10', '01') => __encoding LD1ROW_Z_P_BI_U32 
							when ('11', '00') => __encoding LD1RQD_Z_P_BI_U64 
							when ('11', '01') => __encoding LD1ROD_Z_P_BI_U64 
					when (_, _, _, '0', _, '101', _) => 
						__field dtype 21 +: 4
						__field imm4 16 +: 4
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (dtype) of
							when ('0000') => __encoding LD1B_Z_P_BI_U8 
							when ('0001') => __encoding LD1B_Z_P_BI_U16 
							when ('0010') => __encoding LD1B_Z_P_BI_U32 
							when ('0011') => __encoding LD1B_Z_P_BI_U64 
							when ('0100') => __encoding LD1SW_Z_P_BI_S64 
							when ('0101') => __encoding LD1H_Z_P_BI_U16 
							when ('0110') => __encoding LD1H_Z_P_BI_U32 
							when ('0111') => __encoding LD1H_Z_P_BI_U64 
							when ('1000') => __encoding LD1SH_Z_P_BI_S64 
							when ('1001') => __encoding LD1SH_Z_P_BI_S32 
							when ('1010') => __encoding LD1W_Z_P_BI_U32 
							when ('1011') => __encoding LD1W_Z_P_BI_U64 
							when ('1100') => __encoding LD1SB_Z_P_BI_S64 
							when ('1101') => __encoding LD1SB_Z_P_BI_S32 
							when ('1110') => __encoding LD1SB_Z_P_BI_S16 
							when ('1111') => __encoding LD1D_Z_P_BI_U64 
					when (_, _, _, '1', _, '001', _) => __UNPREDICTABLE
					when (_, _, _, '1', _, '101', _) => 
						__field dtype 21 +: 4
						__field imm4 16 +: 4
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (dtype) of
							when ('0000') => __encoding LDNF1B_Z_P_BI_U8 
							when ('0001') => __encoding LDNF1B_Z_P_BI_U16 
							when ('0010') => __encoding LDNF1B_Z_P_BI_U32 
							when ('0011') => __encoding LDNF1B_Z_P_BI_U64 
							when ('0100') => __encoding LDNF1SW_Z_P_BI_S64 
							when ('0101') => __encoding LDNF1H_Z_P_BI_U16 
							when ('0110') => __encoding LDNF1H_Z_P_BI_U32 
							when ('0111') => __encoding LDNF1H_Z_P_BI_U64 
							when ('1000') => __encoding LDNF1SH_Z_P_BI_S64 
							when ('1001') => __encoding LDNF1SH_Z_P_BI_S32 
							when ('1010') => __encoding LDNF1W_Z_P_BI_U32 
							when ('1011') => __encoding LDNF1W_Z_P_BI_U64 
							when ('1100') => __encoding LDNF1SB_Z_P_BI_S64 
							when ('1101') => __encoding LDNF1SB_Z_P_BI_S32 
							when ('1110') => __encoding LDNF1SB_Z_P_BI_S16 
							when ('1111') => __encoding LDNF1D_Z_P_BI_U64 
					when (_, _, _, '1', _, '111', _) => __UNPREDICTABLE
					when (_, _, _, _, _, '000', _) => 
						__field msz 23 +: 2
						__field ssz 21 +: 2
						__field Rm 16 +: 5
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (msz, ssz) of
							when (_, '1x') => __UNALLOCATED
							when ('00', '00') => __encoding LD1RQB_Z_P_BR_Contiguous 
							when ('00', '01') => __encoding LD1ROB_Z_P_BR_Contiguous 
							when ('01', '00') => __encoding LD1RQH_Z_P_BR_Contiguous 
							when ('01', '01') => __encoding LD1ROH_Z_P_BR_Contiguous 
							when ('10', '00') => __encoding LD1RQW_Z_P_BR_Contiguous 
							when ('10', '01') => __encoding LD1ROW_Z_P_BR_Contiguous 
							when ('11', '00') => __encoding LD1RQD_Z_P_BR_Contiguous 
							when ('11', '01') => __encoding LD1ROD_Z_P_BR_Contiguous 
					when (_, _, _, _, _, '010', _) => 
						__field dtype 21 +: 4
						__field Rm 16 +: 5
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (dtype) of
							when ('0000') => __encoding LD1B_Z_P_BR_U8 
							when ('0001') => __encoding LD1B_Z_P_BR_U16 
							when ('0010') => __encoding LD1B_Z_P_BR_U32 
							when ('0011') => __encoding LD1B_Z_P_BR_U64 
							when ('0100') => __encoding LD1SW_Z_P_BR_S64 
							when ('0101') => __encoding LD1H_Z_P_BR_U16 
							when ('0110') => __encoding LD1H_Z_P_BR_U32 
							when ('0111') => __encoding LD1H_Z_P_BR_U64 
							when ('1000') => __encoding LD1SH_Z_P_BR_S64 
							when ('1001') => __encoding LD1SH_Z_P_BR_S32 
							when ('1010') => __encoding LD1W_Z_P_BR_U32 
							when ('1011') => __encoding LD1W_Z_P_BR_U64 
							when ('1100') => __encoding LD1SB_Z_P_BR_S64 
							when ('1101') => __encoding LD1SB_Z_P_BR_S32 
							when ('1110') => __encoding LD1SB_Z_P_BR_S16 
							when ('1111') => __encoding LD1D_Z_P_BR_U64 
					when (_, _, _, _, _, '011', _) => 
						__field dtype 21 +: 4
						__field Rm 16 +: 5
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (dtype) of
							when ('0000') => __encoding LDFF1B_Z_P_BR_U8 
							when ('0001') => __encoding LDFF1B_Z_P_BR_U16 
							when ('0010') => __encoding LDFF1B_Z_P_BR_U32 
							when ('0011') => __encoding LDFF1B_Z_P_BR_U64 
							when ('0100') => __encoding LDFF1SW_Z_P_BR_S64 
							when ('0101') => __encoding LDFF1H_Z_P_BR_U16 
							when ('0110') => __encoding LDFF1H_Z_P_BR_U32 
							when ('0111') => __encoding LDFF1H_Z_P_BR_U64 
							when ('1000') => __encoding LDFF1SH_Z_P_BR_S64 
							when ('1001') => __encoding LDFF1SH_Z_P_BR_S32 
							when ('1010') => __encoding LDFF1W_Z_P_BR_U32 
							when ('1011') => __encoding LDFF1W_Z_P_BR_U64 
							when ('1100') => __encoding LDFF1SB_Z_P_BR_S64 
							when ('1101') => __encoding LDFF1SB_Z_P_BR_S32 
							when ('1110') => __encoding LDFF1SB_Z_P_BR_S16 
							when ('1111') => __encoding LDFF1D_Z_P_BR_U64 
					when (_, _, _, _, _, '100', _) => __UNPREDICTABLE
			when ('110', _, _, _, _, _, _, _) =>
				case (25 +: 7, 23 +: 2, 21 +: 2, 16 +: 5, 13 +: 3, 5 +: 8, 4 +: 1, 0 +: 4) of
					when (_, '00', '01', _, '0xx', _, '1', _) => __UNPREDICTABLE
					when (_, '00', '11', _, '1xx', _, '0', _) => 
						__field Zm 16 +: 5
						__field msz 13 +: 2
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field prfop 0 +: 4
						case (msz) of
							when ('00') => __encoding PRFB_I_P_BZ_D_64_scaled 
							when ('01') => __encoding PRFH_I_P_BZ_D_64_scaled 
							when ('10') => __encoding PRFW_I_P_BZ_D_64_scaled 
							when ('11') => __encoding PRFD_I_P_BZ_D_64_scaled 
					when (_, '00', '11', _, _, _, '1', _) => __UNPREDICTABLE
					when (_, '00', 'x1', _, '0xx', _, '0', _) => 
						__field xs 22 +: 1
						__field Zm 16 +: 5
						__field msz 13 +: 2
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field prfop 0 +: 4
						case (msz) of
							when ('00') => __encoding PRFB_I_P_BZ_D_x32_scaled 
							when ('01') => __encoding PRFH_I_P_BZ_D_x32_scaled 
							when ('10') => __encoding PRFW_I_P_BZ_D_x32_scaled 
							when ('11') => __encoding PRFD_I_P_BZ_D_x32_scaled 
					when (_, !'00', '11', _, '1xx', _, _, _) => 
						__field opc 23 +: 2
						__field Zm 16 +: 5
						__field U 14 +: 1
						__field ff 13 +: 1
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (opc, U, ff) of
							when ('01', '0', '0') => __encoding LD1SH_Z_P_BZ_D_64_scaled 
							when ('01', '0', '1') => __encoding LDFF1SH_Z_P_BZ_D_64_scaled 
							when ('01', '1', '0') => __encoding LD1H_Z_P_BZ_D_64_scaled 
							when ('01', '1', '1') => __encoding LDFF1H_Z_P_BZ_D_64_scaled 
							when ('10', '0', '0') => __encoding LD1SW_Z_P_BZ_D_64_scaled 
							when ('10', '0', '1') => __encoding LDFF1SW_Z_P_BZ_D_64_scaled 
							when ('10', '1', '0') => __encoding LD1W_Z_P_BZ_D_64_scaled 
							when ('10', '1', '1') => __encoding LDFF1W_Z_P_BZ_D_64_scaled 
							when ('11', '0', _) => __UNALLOCATED
							when ('11', '1', '0') => __encoding LD1D_Z_P_BZ_D_64_scaled 
							when ('11', '1', '1') => __encoding LDFF1D_Z_P_BZ_D_64_scaled 
					when (_, !'00', 'x1', _, '0xx', _, _, _) => 
						__field opc 23 +: 2
						__field xs 22 +: 1
						__field Zm 16 +: 5
						__field U 14 +: 1
						__field ff 13 +: 1
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (opc, U, ff) of
							when ('01', '0', '0') => __encoding LD1SH_Z_P_BZ_D_x32_scaled 
							when ('01', '0', '1') => __encoding LDFF1SH_Z_P_BZ_D_x32_scaled 
							when ('01', '1', '0') => __encoding LD1H_Z_P_BZ_D_x32_scaled 
							when ('01', '1', '1') => __encoding LDFF1H_Z_P_BZ_D_x32_scaled 
							when ('10', '0', '0') => __encoding LD1SW_Z_P_BZ_D_x32_scaled 
							when ('10', '0', '1') => __encoding LDFF1SW_Z_P_BZ_D_x32_scaled 
							when ('10', '1', '0') => __encoding LD1W_Z_P_BZ_D_x32_scaled 
							when ('10', '1', '1') => __encoding LDFF1W_Z_P_BZ_D_x32_scaled 
							when ('11', '0', _) => __UNALLOCATED
							when ('11', '1', '0') => __encoding LD1D_Z_P_BZ_D_x32_scaled 
							when ('11', '1', '1') => __encoding LDFF1D_Z_P_BZ_D_x32_scaled 
					when (_, _, '00', _, '10x', _, _, _) => __UNPREDICTABLE
					when (_, _, '00', _, '110', _, _, _) => __UNPREDICTABLE
					when (_, _, '00', _, '111', _, '0', _) => 
						__field msz 23 +: 2
						__field imm5 16 +: 5
						__field Pg 10 +: 3
						__field Zn 5 +: 5
						__field prfop 0 +: 4
						case (msz) of
							when ('00') => __encoding PRFB_I_P_AI_D 
							when ('01') => __encoding PRFH_I_P_AI_D 
							when ('10') => __encoding PRFW_I_P_AI_D 
							when ('11') => __encoding PRFD_I_P_AI_D 
					when (_, _, '00', _, '111', _, '1', _) => __UNPREDICTABLE
					when (_, _, '01', _, '1xx', _, _, _) => 
						__field msz 23 +: 2
						__field imm5 16 +: 5
						__field U 14 +: 1
						__field ff 13 +: 1
						__field Pg 10 +: 3
						__field Zn 5 +: 5
						__field Zt 0 +: 5
						case (msz, U, ff) of
							when ('00', '0', '0') => __encoding LD1SB_Z_P_AI_D 
							when ('00', '0', '1') => __encoding LDFF1SB_Z_P_AI_D 
							when ('00', '1', '0') => __encoding LD1B_Z_P_AI_D 
							when ('00', '1', '1') => __encoding LDFF1B_Z_P_AI_D 
							when ('01', '0', '0') => __encoding LD1SH_Z_P_AI_D 
							when ('01', '0', '1') => __encoding LDFF1SH_Z_P_AI_D 
							when ('01', '1', '0') => __encoding LD1H_Z_P_AI_D 
							when ('01', '1', '1') => __encoding LDFF1H_Z_P_AI_D 
							when ('10', '0', '0') => __encoding LD1SW_Z_P_AI_D 
							when ('10', '0', '1') => __encoding LDFF1SW_Z_P_AI_D 
							when ('10', '1', '0') => __encoding LD1W_Z_P_AI_D 
							when ('10', '1', '1') => __encoding LDFF1W_Z_P_AI_D 
							when ('11', '0', _) => __UNALLOCATED
							when ('11', '1', '0') => __encoding LD1D_Z_P_AI_D 
							when ('11', '1', '1') => __encoding LDFF1D_Z_P_AI_D 
					when (_, _, '10', _, '1xx', _, _, _) => 
						__field msz 23 +: 2
						__field Zm 16 +: 5
						__field U 14 +: 1
						__field ff 13 +: 1
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (msz, U, ff) of
							when ('00', '0', '0') => __encoding LD1SB_Z_P_BZ_D_64_unscaled 
							when ('00', '0', '1') => __encoding LDFF1SB_Z_P_BZ_D_64_unscaled 
							when ('00', '1', '0') => __encoding LD1B_Z_P_BZ_D_64_unscaled 
							when ('00', '1', '1') => __encoding LDFF1B_Z_P_BZ_D_64_unscaled 
							when ('01', '0', '0') => __encoding LD1SH_Z_P_BZ_D_64_unscaled 
							when ('01', '0', '1') => __encoding LDFF1SH_Z_P_BZ_D_64_unscaled 
							when ('01', '1', '0') => __encoding LD1H_Z_P_BZ_D_64_unscaled 
							when ('01', '1', '1') => __encoding LDFF1H_Z_P_BZ_D_64_unscaled 
							when ('10', '0', '0') => __encoding LD1SW_Z_P_BZ_D_64_unscaled 
							when ('10', '0', '1') => __encoding LDFF1SW_Z_P_BZ_D_64_unscaled 
							when ('10', '1', '0') => __encoding LD1W_Z_P_BZ_D_64_unscaled 
							when ('10', '1', '1') => __encoding LDFF1W_Z_P_BZ_D_64_unscaled 
							when ('11', '0', _) => __UNALLOCATED
							when ('11', '1', '0') => __encoding LD1D_Z_P_BZ_D_64_unscaled 
							when ('11', '1', '1') => __encoding LDFF1D_Z_P_BZ_D_64_unscaled 
					when (_, _, 'x0', _, '0xx', _, _, _) => 
						__field msz 23 +: 2
						__field xs 22 +: 1
						__field Zm 16 +: 5
						__field U 14 +: 1
						__field ff 13 +: 1
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (msz, U, ff) of
							when ('00', '0', '0') => __encoding LD1SB_Z_P_BZ_D_x32_unscaled 
							when ('00', '0', '1') => __encoding LDFF1SB_Z_P_BZ_D_x32_unscaled 
							when ('00', '1', '0') => __encoding LD1B_Z_P_BZ_D_x32_unscaled 
							when ('00', '1', '1') => __encoding LDFF1B_Z_P_BZ_D_x32_unscaled 
							when ('01', '0', '0') => __encoding LD1SH_Z_P_BZ_D_x32_unscaled 
							when ('01', '0', '1') => __encoding LDFF1SH_Z_P_BZ_D_x32_unscaled 
							when ('01', '1', '0') => __encoding LD1H_Z_P_BZ_D_x32_unscaled 
							when ('01', '1', '1') => __encoding LDFF1H_Z_P_BZ_D_x32_unscaled 
							when ('10', '0', '0') => __encoding LD1SW_Z_P_BZ_D_x32_unscaled 
							when ('10', '0', '1') => __encoding LDFF1SW_Z_P_BZ_D_x32_unscaled 
							when ('10', '1', '0') => __encoding LD1W_Z_P_BZ_D_x32_unscaled 
							when ('10', '1', '1') => __encoding LDFF1W_Z_P_BZ_D_x32_unscaled 
							when ('11', '0', _) => __UNALLOCATED
							when ('11', '1', '0') => __encoding LD1D_Z_P_BZ_D_x32_unscaled 
							when ('11', '1', '1') => __encoding LDFF1D_Z_P_BZ_D_x32_unscaled 
			when ('111', _, _, _, _, _, '0x0xxx', _) =>
				case (25 +: 7, 22 +: 3, 16 +: 6, 15 +: 1, 14 +: 1, 13 +: 1, 5 +: 8, 4 +: 1, 0 +: 4) of
					when (_, '0xx', _, _, '0', _, _, _, _) => __UNPREDICTABLE
					when (_, '10x', _, _, '0', _, _, _, _) => __UNPREDICTABLE
					when (_, '110', _, _, '0', _, _, '0', _) => 
						__field imm9h 16 +: 6
						__field imm9l 10 +: 3
						__field Rn 5 +: 5
						__field Pt 0 +: 4
						case () of
							when () => __encoding STR_P_BI__ 
					when (_, '110', _, _, '0', _, _, '1', _) => __UNPREDICTABLE
					when (_, '110', _, _, '1', _, _, _, _) => 
						__field imm9h 16 +: 6
						__field imm9l 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case () of
							when () => __encoding STR_Z_BI__ 
					when (_, '111', _, _, '0', _, _, _, _) => __UNPREDICTABLE
					when (_, !'110', _, _, '1', _, _, _, _) => 
						__field opc 22 +: 3
						__field o2 21 +: 1
						__field Rm 16 +: 5
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (opc, o2) of
							when ('00x', _) => __encoding ST1B_Z_P_BR__ 
							when ('01x', _) => __encoding ST1H_Z_P_BR__ 
							when ('10x', _) => __encoding ST1W_Z_P_BR__ 
							when ('111', '0') => __UNALLOCATED
							when ('111', '1') => __encoding ST1D_Z_P_BR__ 
			when ('111', _, _, _, _, _, '0x1xxx', _) =>
				case (25 +: 7, 23 +: 2, 21 +: 2, 16 +: 5, 15 +: 1, 14 +: 1, 13 +: 1, 0 +: 13) of
					when (_, _, '00', _, _, '1', _, _) => 
						__field msz 23 +: 2
						__field Rm 16 +: 5
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (msz) of
							when ('00') => __encoding STNT1B_Z_P_BR_Contiguous 
							when ('01') => __encoding STNT1H_Z_P_BR_Contiguous 
							when ('10') => __encoding STNT1W_Z_P_BR_Contiguous 
							when ('11') => __encoding STNT1D_Z_P_BR_Contiguous 
					when (_, _, !'00', _, _, '1', _, _) => 
						__field msz 23 +: 2
						__field opc 21 +: 2
						__field Rm 16 +: 5
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (msz, opc) of
							when ('00', '01') => __encoding ST2B_Z_P_BR_Contiguous 
							when ('00', '10') => __encoding ST3B_Z_P_BR_Contiguous 
							when ('00', '11') => __encoding ST4B_Z_P_BR_Contiguous 
							when ('01', '01') => __encoding ST2H_Z_P_BR_Contiguous 
							when ('01', '10') => __encoding ST3H_Z_P_BR_Contiguous 
							when ('01', '11') => __encoding ST4H_Z_P_BR_Contiguous 
							when ('10', '01') => __encoding ST2W_Z_P_BR_Contiguous 
							when ('10', '10') => __encoding ST3W_Z_P_BR_Contiguous 
							when ('10', '11') => __encoding ST4W_Z_P_BR_Contiguous 
							when ('11', '01') => __encoding ST2D_Z_P_BR_Contiguous 
							when ('11', '10') => __encoding ST3D_Z_P_BR_Contiguous 
							when ('11', '11') => __encoding ST4D_Z_P_BR_Contiguous 
					when (_, _, _, _, _, '0', _, _) => __UNPREDICTABLE
			when ('111', _, _, _, _, _, '1x0xxx', _) =>
				case (25 +: 7, 23 +: 2, 21 +: 2, 16 +: 5, 15 +: 1, 14 +: 1, 13 +: 1, 0 +: 13) of
					when (_, _, '00', _, _, _, _, _) => 
						__field msz 23 +: 2
						__field Zm 16 +: 5
						__field xs 14 +: 1
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (msz) of
							when ('00') => __encoding ST1B_Z_P_BZ_D_x32_unscaled 
							when ('01') => __encoding ST1H_Z_P_BZ_D_x32_unscaled 
							when ('10') => __encoding ST1W_Z_P_BZ_D_x32_unscaled 
							when ('11') => __encoding ST1D_Z_P_BZ_D_x32_unscaled 
					when (_, _, '01', _, _, _, _, _) => 
						__field msz 23 +: 2
						__field Zm 16 +: 5
						__field xs 14 +: 1
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (msz) of
							when ('00') => __UNALLOCATED
							when ('01') => __encoding ST1H_Z_P_BZ_D_x32_scaled 
							when ('10') => __encoding ST1W_Z_P_BZ_D_x32_scaled 
							when ('11') => __encoding ST1D_Z_P_BZ_D_x32_scaled 
					when (_, _, '10', _, _, _, _, _) => 
						__field msz 23 +: 2
						__field Zm 16 +: 5
						__field xs 14 +: 1
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (msz) of
							when ('00') => __encoding ST1B_Z_P_BZ_S_x32_unscaled 
							when ('01') => __encoding ST1H_Z_P_BZ_S_x32_unscaled 
							when ('10') => __encoding ST1W_Z_P_BZ_S_x32_unscaled 
							when ('11') => __UNALLOCATED
					when (_, _, '11', _, _, _, _, _) => 
						__field msz 23 +: 2
						__field Zm 16 +: 5
						__field xs 14 +: 1
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (msz) of
							when ('00') => __UNALLOCATED
							when ('01') => __encoding ST1H_Z_P_BZ_S_x32_scaled 
							when ('10') => __encoding ST1W_Z_P_BZ_S_x32_scaled 
							when ('11') => __UNALLOCATED
			when ('111', _, _, _, _, _, '101xxx', _) =>
				case (25 +: 7, 23 +: 2, 21 +: 2, 16 +: 5, 13 +: 3, 0 +: 13) of
					when (_, _, '00', _, _, _) => 
						__field msz 23 +: 2
						__field Zm 16 +: 5
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (msz) of
							when ('00') => __encoding ST1B_Z_P_BZ_D_64_unscaled 
							when ('01') => __encoding ST1H_Z_P_BZ_D_64_unscaled 
							when ('10') => __encoding ST1W_Z_P_BZ_D_64_unscaled 
							when ('11') => __encoding ST1D_Z_P_BZ_D_64_unscaled 
					when (_, _, '01', _, _, _) => 
						__field msz 23 +: 2
						__field Zm 16 +: 5
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (msz) of
							when ('00') => __UNALLOCATED
							when ('01') => __encoding ST1H_Z_P_BZ_D_64_scaled 
							when ('10') => __encoding ST1W_Z_P_BZ_D_64_scaled 
							when ('11') => __encoding ST1D_Z_P_BZ_D_64_scaled 
					when (_, _, '10', _, _, _) => 
						__field msz 23 +: 2
						__field imm5 16 +: 5
						__field Pg 10 +: 3
						__field Zn 5 +: 5
						__field Zt 0 +: 5
						case (msz) of
							when ('00') => __encoding ST1B_Z_P_AI_D 
							when ('01') => __encoding ST1H_Z_P_AI_D 
							when ('10') => __encoding ST1W_Z_P_AI_D 
							when ('11') => __encoding ST1D_Z_P_AI_D 
					when (_, _, '11', _, _, _) => 
						__field msz 23 +: 2
						__field imm5 16 +: 5
						__field Pg 10 +: 3
						__field Zn 5 +: 5
						__field Zt 0 +: 5
						case (msz) of
							when ('00') => __encoding ST1B_Z_P_AI_S 
							when ('01') => __encoding ST1H_Z_P_AI_S 
							when ('10') => __encoding ST1W_Z_P_AI_S 
							when ('11') => __UNALLOCATED
			when ('111', _, _, _, _, _, '111xxx', _) =>
				case (25 +: 7, 23 +: 2, 21 +: 2, 20 +: 1, 16 +: 4, 13 +: 3, 0 +: 13) of
					when (_, _, '00', '1', _, _, _) => 
						__field msz 23 +: 2
						__field imm4 16 +: 4
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (msz) of
							when ('00') => __encoding STNT1B_Z_P_BI_Contiguous 
							when ('01') => __encoding STNT1H_Z_P_BI_Contiguous 
							when ('10') => __encoding STNT1W_Z_P_BI_Contiguous 
							when ('11') => __encoding STNT1D_Z_P_BI_Contiguous 
					when (_, _, !'00', '1', _, _, _) => 
						__field msz 23 +: 2
						__field opc 21 +: 2
						__field imm4 16 +: 4
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (msz, opc) of
							when ('00', '01') => __encoding ST2B_Z_P_BI_Contiguous 
							when ('00', '10') => __encoding ST3B_Z_P_BI_Contiguous 
							when ('00', '11') => __encoding ST4B_Z_P_BI_Contiguous 
							when ('01', '01') => __encoding ST2H_Z_P_BI_Contiguous 
							when ('01', '10') => __encoding ST3H_Z_P_BI_Contiguous 
							when ('01', '11') => __encoding ST4H_Z_P_BI_Contiguous 
							when ('10', '01') => __encoding ST2W_Z_P_BI_Contiguous 
							when ('10', '10') => __encoding ST3W_Z_P_BI_Contiguous 
							when ('10', '11') => __encoding ST4W_Z_P_BI_Contiguous 
							when ('11', '01') => __encoding ST2D_Z_P_BI_Contiguous 
							when ('11', '10') => __encoding ST3D_Z_P_BI_Contiguous 
							when ('11', '11') => __encoding ST4D_Z_P_BI_Contiguous 
					when (_, _, _, '0', _, _, _) => 
						__field msz 23 +: 2
						__field size 21 +: 2
						__field imm4 16 +: 4
						__field Pg 10 +: 3
						__field Rn 5 +: 5
						__field Zt 0 +: 5
						case (msz) of
							when ('00') => __encoding ST1B_Z_P_BI__ 
							when ('01') => __encoding ST1H_Z_P_BI__ 
							when ('10') => __encoding ST1W_Z_P_BI__ 
							when ('11') => __encoding ST1D_Z_P_BI__ 
	when (_, '0011x', _) => __UNPREDICTABLE
	when (_, '100xx', _) =>
		case (29 +: 3, 26 +: 3, 23 +: 3, 0 +: 23) of
			when (_, _, '00x', _) => 
				__field op 31 +: 1
				__field immlo 29 +: 2
				__field immhi 5 +: 19
				__field Rd 0 +: 5
				case (op) of
					when ('0') => __encoding aarch64_integer_arithmetic_address_pc_rel 
					when ('1') => __encoding aarch64_integer_arithmetic_address_pc_rel 
			when (_, _, '010', _) => 
				__field sf 31 +: 1
				__field op 30 +: 1
				__field S 29 +: 1
				__field sh 22 +: 1
				__field imm12 10 +: 12
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (sf, op, S) of
					when ('0', '0', '0') => __encoding aarch64_integer_arithmetic_add_sub_immediate 
					when ('0', '0', '1') => __encoding aarch64_integer_arithmetic_add_sub_immediate 
					when ('0', '1', '0') => __encoding aarch64_integer_arithmetic_add_sub_immediate 
					when ('0', '1', '1') => __encoding aarch64_integer_arithmetic_add_sub_immediate 
					when ('1', '0', '0') => __encoding aarch64_integer_arithmetic_add_sub_immediate 
					when ('1', '0', '1') => __encoding aarch64_integer_arithmetic_add_sub_immediate 
					when ('1', '1', '0') => __encoding aarch64_integer_arithmetic_add_sub_immediate 
					when ('1', '1', '1') => __encoding aarch64_integer_arithmetic_add_sub_immediate 
			when (_, _, '011', _) => 
				__field sf 31 +: 1
				__field op 30 +: 1
				__field S 29 +: 1
				__field o2 22 +: 1
				__field uimm6 16 +: 6
				__field op3 14 +: 2
				__field uimm4 10 +: 4
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (sf, op, S, o2) of
					when (_, _, _, '1') => __UNALLOCATED
					when ('0', _, _, '0') => __UNALLOCATED
					when ('1', _, '1', '0') => __UNALLOCATED
					when ('1', '0', '0', '0') => __encoding aarch64_integer_tags_mcaddtag 
					when ('1', '1', '0', '0') => __encoding aarch64_integer_tags_mcsubtag 
			when (_, _, '100', _) => 
				__field sf 31 +: 1
				__field opc 29 +: 2
				__field N 22 +: 1
				__field immr 16 +: 6
				__field imms 10 +: 6
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (sf, opc, N) of
					when ('0', _, '1') => __UNALLOCATED
					when ('0', '00', '0') => __encoding aarch64_integer_logical_immediate 
					when ('0', '01', '0') => __encoding aarch64_integer_logical_immediate 
					when ('0', '10', '0') => __encoding aarch64_integer_logical_immediate 
					when ('0', '11', '0') => __encoding aarch64_integer_logical_immediate 
					when ('1', '00', _) => __encoding aarch64_integer_logical_immediate 
					when ('1', '01', _) => __encoding aarch64_integer_logical_immediate 
					when ('1', '10', _) => __encoding aarch64_integer_logical_immediate 
					when ('1', '11', _) => __encoding aarch64_integer_logical_immediate 
			when (_, _, '101', _) => 
				__field sf 31 +: 1
				__field opc 29 +: 2
				__field hw 21 +: 2
				__field imm16 5 +: 16
				__field Rd 0 +: 5
				case (sf, opc, hw) of
					when (_, '01', _) => __UNALLOCATED
					when ('0', _, '1x') => __UNALLOCATED
					when ('0', '00', '0x') => __encoding aarch64_integer_ins_ext_insert_movewide 
					when ('0', '10', '0x') => __encoding aarch64_integer_ins_ext_insert_movewide 
					when ('0', '11', '0x') => __encoding aarch64_integer_ins_ext_insert_movewide 
					when ('1', '00', _) => __encoding aarch64_integer_ins_ext_insert_movewide 
					when ('1', '10', _) => __encoding aarch64_integer_ins_ext_insert_movewide 
					when ('1', '11', _) => __encoding aarch64_integer_ins_ext_insert_movewide 
			when (_, _, '110', _) => 
				__field sf 31 +: 1
				__field opc 29 +: 2
				__field N 22 +: 1
				__field immr 16 +: 6
				__field imms 10 +: 6
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (sf, opc, N) of
					when (_, '11', _) => __UNALLOCATED
					when ('0', _, '1') => __UNALLOCATED
					when ('0', '00', '0') => __encoding aarch64_integer_bitfield 
					when ('0', '01', '0') => __encoding aarch64_integer_bitfield 
					when ('0', '10', '0') => __encoding aarch64_integer_bitfield 
					when ('1', _, '0') => __UNALLOCATED
					when ('1', '00', '1') => __encoding aarch64_integer_bitfield 
					when ('1', '01', '1') => __encoding aarch64_integer_bitfield 
					when ('1', '10', '1') => __encoding aarch64_integer_bitfield 
			when (_, _, '111', _) => 
				__field sf 31 +: 1
				__field op21 29 +: 2
				__field N 22 +: 1
				__field o0 21 +: 1
				__field Rm 16 +: 5
				__field imms 10 +: 6
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (sf, op21, N, o0, imms) of
					when (_, 'x1', _, _, _) => __UNALLOCATED
					when (_, '00', _, '1', _) => __UNALLOCATED
					when (_, '1x', _, _, _) => __UNALLOCATED
					when ('0', _, _, _, '1xxxxx') => __UNALLOCATED
					when ('0', _, '1', _, _) => __UNALLOCATED
					when ('0', '00', '0', '0', '0xxxxx') => __encoding aarch64_integer_ins_ext_extract_immediate 
					when ('1', _, '0', _, _) => __UNALLOCATED
					when ('1', '00', '1', '0', _) => __encoding aarch64_integer_ins_ext_extract_immediate 
	when (_, '101xx', _) =>
		case (29 +: 3, 26 +: 3, 12 +: 14, 5 +: 7, 0 +: 5) of
			when ('010', _, '0xxxxxxxxxxxxx', _, _) => 
				__field o1 24 +: 1
				__field imm19 5 +: 19
				__field o0 4 +: 1
				__field cond 0 +: 4
				case (o1, o0) of
					when ('0', '0') => __encoding aarch64_branch_conditional_cond 
					when ('0', '1') => __UNALLOCATED
					when ('1', _) => __UNALLOCATED
			when ('110', _, '00xxxxxxxxxxxx', _, _) => 
				__field opc 21 +: 3
				__field imm16 5 +: 16
				__field op2 2 +: 3
				__field LL 0 +: 2
				case (opc, op2, LL) of
					when (_, '001', _) => __UNALLOCATED
					when (_, '01x', _) => __UNALLOCATED
					when (_, '1xx', _) => __UNALLOCATED
					when ('000', '000', '00') => __UNALLOCATED
					when ('000', '000', '01') => __encoding aarch64_system_exceptions_runtime_svc 
					when ('000', '000', '10') => __encoding aarch64_system_exceptions_runtime_hvc 
					when ('000', '000', '11') => __encoding aarch64_system_exceptions_runtime_smc 
					when ('001', '000', 'x1') => __UNALLOCATED
					when ('001', '000', '00') => __encoding aarch64_system_exceptions_debug_breakpoint 
					when ('001', '000', '1x') => __UNALLOCATED
					when ('010', '000', 'x1') => __UNALLOCATED
					when ('010', '000', '00') => __encoding aarch64_system_exceptions_debug_halt 
					when ('010', '000', '1x') => __UNALLOCATED
					when ('011', '000', '01') => __UNALLOCATED
					when ('011', '000', '1x') => __UNALLOCATED
					when ('100', '000', _) => __UNALLOCATED
					when ('101', '000', '00') => __UNALLOCATED
					when ('101', '000', '01') => __encoding aarch64_system_exceptions_debug_exception 
					when ('101', '000', '10') => __encoding aarch64_system_exceptions_debug_exception 
					when ('101', '000', '11') => __encoding aarch64_system_exceptions_debug_exception 
					when ('110', '000', _) => __UNALLOCATED
					when ('111', '000', _) => __UNALLOCATED
			when ('110', _, '01000000110010', _, '11111') => 
				__field CRm 8 +: 4
				__field op2 5 +: 3
				case (CRm, op2) of
					when (_, _) => __encoding aarch64_system_hints 
					when ('0000', '000') => __encoding aarch64_system_hints 
					when ('0000', '001') => __encoding aarch64_system_hints 
					when ('0000', '010') => __encoding aarch64_system_hints 
					when ('0000', '011') => __encoding aarch64_system_hints 
					when ('0000', '100') => __encoding aarch64_system_hints 
					when ('0000', '101') => __encoding aarch64_system_hints 
					when ('0000', '110') => __encoding aarch64_system_hints 
					when ('0000', '111') => __encoding aarch64_integer_pac_strip_hint 
					when ('0001', '000') => __encoding aarch64_integer_pac_pacia_hint 
					when ('0001', '010') => __encoding aarch64_integer_pac_pacib_hint 
					when ('0001', '100') => __encoding aarch64_integer_pac_autia_hint 
					when ('0001', '110') => __encoding aarch64_integer_pac_autib_hint 
					when ('0010', '000') => __encoding aarch64_system_hints 
					when ('0010', '001') => __encoding aarch64_system_hints 
					when ('0010', '010') => __encoding aarch64_system_hints 
					when ('0010', '100') => __encoding aarch64_system_hints 
					when ('0011', '000') => __encoding aarch64_integer_pac_pacia_hint 
					when ('0011', '001') => __encoding aarch64_integer_pac_pacia_hint 
					when ('0011', '010') => __encoding aarch64_integer_pac_pacib_hint 
					when ('0011', '011') => __encoding aarch64_integer_pac_pacib_hint 
					when ('0011', '100') => __encoding aarch64_integer_pac_autia_hint 
					when ('0011', '101') => __encoding aarch64_integer_pac_autia_hint 
					when ('0011', '110') => __encoding aarch64_integer_pac_autib_hint 
					when ('0011', '111') => __encoding aarch64_integer_pac_autib_hint 
					when ('0100', 'xx0') => __encoding aarch64_system_hints 
			when ('110', _, '01000000110011', _, _) => 
				__field CRm 8 +: 4
				__field op2 5 +: 3
				__field Rt 0 +: 5
				case (CRm, op2, Rt) of
					when (_, '000', _) => __UNALLOCATED
					when (_, '001', _) => __UNALLOCATED
					when (_, '010', '11111') => __encoding aarch64_system_monitors 
					when (_, '101', '11111') => __encoding aarch64_system_barriers_dmb 
					when (_, '110', '11111') => __encoding aarch64_system_barriers_isb 
					when (_, '111', !'11111') => __UNALLOCATED
					when (_, '111', '11111') => __encoding aarch64_system_barriers_sb 
					when (!'0x00', '100', '11111') => __encoding aarch64_system_barriers_dsb 
					when ('0000', '100', '11111') => __encoding aarch64_system_barriers_ssbb 
					when ('0001', '011', _) => __UNALLOCATED
					when ('001x', '011', _) => __UNALLOCATED
					when ('01xx', '011', _) => __UNALLOCATED
					when ('0100', '100', '11111') => __encoding aarch64_system_barriers_pssbb 
					when ('1xxx', '011', _) => __UNALLOCATED
			when ('110', _, '0100000xxx0100', _, _) => 
				__field op1 16 +: 3
				__field CRm 8 +: 4
				__field op2 5 +: 3
				__field Rt 0 +: 5
				case (op1, op2, Rt) of
					when (_, _, !'11111') => __UNALLOCATED
					when (_, _, '11111') => __encoding aarch64_system_register_cpsr 
					when ('000', '000', '11111') => __encoding aarch64_integer_flags_cfinv 
					when ('000', '001', '11111') => __encoding aarch64_integer_flags_xaflag 
					when ('000', '010', '11111') => __encoding aarch64_integer_flags_axflag 
			when ('110', _, '0100x01xxxxxxx', _, _) => 
				__field L 21 +: 1
				__field op1 16 +: 3
				__field CRn 12 +: 4
				__field CRm 8 +: 4
				__field op2 5 +: 3
				__field Rt 0 +: 5
				case (L) of
					when ('0') => __encoding aarch64_system_sysops 
					when ('1') => __encoding aarch64_system_sysops 
			when ('110', _, '0100x1xxxxxxxx', _, _) => 
				__field L 21 +: 1
				__field o0 19 +: 1
				__field op1 16 +: 3
				__field CRn 12 +: 4
				__field CRm 8 +: 4
				__field op2 5 +: 3
				__field Rt 0 +: 5
				case (L) of
					when ('0') => __encoding aarch64_system_register_system 
					when ('1') => __encoding aarch64_system_register_system 
			when ('110', _, '1xxxxxxxxxxxxx', _, _) => 
				__field opc 21 +: 4
				__field op2 16 +: 5
				__field op3 10 +: 6
				__field Rn 5 +: 5
				__field op4 0 +: 5
				case (opc, op2, op3, Rn, op4) of
					when (_, !'11111', _, _, _) => __UNALLOCATED
					when ('0000', '11111', '000000', _, !'00000') => __UNALLOCATED
					when ('0000', '11111', '000000', _, '00000') => __encoding aarch64_branch_unconditional_register 
					when ('0000', '11111', '000001', _, _) => __UNALLOCATED
					when ('0000', '11111', '000010', _, !'11111') => __UNALLOCATED
					when ('0000', '11111', '000010', _, '11111') => __encoding aarch64_branch_unconditional_register 
					when ('0000', '11111', '000011', _, !'11111') => __UNALLOCATED
					when ('0000', '11111', '000011', _, '11111') => __encoding aarch64_branch_unconditional_register 
					when ('0000', '11111', '0001xx', _, _) => __UNALLOCATED
					when ('0000', '11111', '001xxx', _, _) => __UNALLOCATED
					when ('0000', '11111', '01xxxx', _, _) => __UNALLOCATED
					when ('0000', '11111', '1xxxxx', _, _) => __UNALLOCATED
					when ('0001', '11111', '000000', _, !'00000') => __UNALLOCATED
					when ('0001', '11111', '000000', _, '00000') => __encoding aarch64_branch_unconditional_register 
					when ('0001', '11111', '000001', _, _) => __UNALLOCATED
					when ('0001', '11111', '000010', _, !'11111') => __UNALLOCATED
					when ('0001', '11111', '000010', _, '11111') => __encoding aarch64_branch_unconditional_register 
					when ('0001', '11111', '000011', _, !'11111') => __UNALLOCATED
					when ('0001', '11111', '000011', _, '11111') => __encoding aarch64_branch_unconditional_register 
					when ('0001', '11111', '0001xx', _, _) => __UNALLOCATED
					when ('0001', '11111', '001xxx', _, _) => __UNALLOCATED
					when ('0001', '11111', '01xxxx', _, _) => __UNALLOCATED
					when ('0001', '11111', '1xxxxx', _, _) => __UNALLOCATED
					when ('0010', '11111', '000000', _, !'00000') => __UNALLOCATED
					when ('0010', '11111', '000000', _, '00000') => __encoding aarch64_branch_unconditional_register 
					when ('0010', '11111', '000001', _, _) => __UNALLOCATED
					when ('0010', '11111', '000010', !'11111', !'11111') => __UNALLOCATED
					when ('0010', '11111', '000010', '11111', '11111') => __encoding aarch64_branch_unconditional_register 
					when ('0010', '11111', '000011', !'11111', !'11111') => __UNALLOCATED
					when ('0010', '11111', '000011', '11111', '11111') => __encoding aarch64_branch_unconditional_register 
					when ('0010', '11111', '0001xx', _, _) => __UNALLOCATED
					when ('0010', '11111', '001xxx', _, _) => __UNALLOCATED
					when ('0010', '11111', '01xxxx', _, _) => __UNALLOCATED
					when ('0010', '11111', '1xxxxx', _, _) => __UNALLOCATED
					when ('0011', '11111', _, _, _) => __UNALLOCATED
					when ('0100', '11111', '000000', !'11111', !'00000') => __UNALLOCATED
					when ('0100', '11111', '000000', !'11111', '00000') => __UNALLOCATED
					when ('0100', '11111', '000000', '11111', !'00000') => __UNALLOCATED
					when ('0100', '11111', '000000', '11111', '00000') => __encoding aarch64_branch_unconditional_eret 
					when ('0100', '11111', '000001', _, _) => __UNALLOCATED
					when ('0100', '11111', '000010', !'11111', !'11111') => __UNALLOCATED
					when ('0100', '11111', '000010', !'11111', '11111') => __UNALLOCATED
					when ('0100', '11111', '000010', '11111', !'11111') => __UNALLOCATED
					when ('0100', '11111', '000010', '11111', '11111') => __encoding aarch64_branch_unconditional_eret 
					when ('0100', '11111', '000011', !'11111', !'11111') => __UNALLOCATED
					when ('0100', '11111', '000011', !'11111', '11111') => __UNALLOCATED
					when ('0100', '11111', '000011', '11111', !'11111') => __UNALLOCATED
					when ('0100', '11111', '000011', '11111', '11111') => __encoding aarch64_branch_unconditional_eret 
					when ('0100', '11111', '0001xx', _, _) => __UNALLOCATED
					when ('0100', '11111', '001xxx', _, _) => __UNALLOCATED
					when ('0100', '11111', '01xxxx', _, _) => __UNALLOCATED
					when ('0100', '11111', '1xxxxx', _, _) => __UNALLOCATED
					when ('0101', '11111', !'000000', _, _) => __UNALLOCATED
					when ('0101', '11111', '000000', !'11111', !'00000') => __UNALLOCATED
					when ('0101', '11111', '000000', !'11111', '00000') => __UNALLOCATED
					when ('0101', '11111', '000000', '11111', !'00000') => __UNALLOCATED
					when ('0101', '11111', '000000', '11111', '00000') => __encoding aarch64_branch_unconditional_dret 
					when ('011x', '11111', _, _, _) => __UNALLOCATED
					when ('1000', '11111', '00000x', _, _) => __UNALLOCATED
					when ('1000', '11111', '000010', _, _) => __encoding aarch64_branch_unconditional_register 
					when ('1000', '11111', '000011', _, _) => __encoding aarch64_branch_unconditional_register 
					when ('1000', '11111', '0001xx', _, _) => __UNALLOCATED
					when ('1000', '11111', '001xxx', _, _) => __UNALLOCATED
					when ('1000', '11111', '01xxxx', _, _) => __UNALLOCATED
					when ('1000', '11111', '1xxxxx', _, _) => __UNALLOCATED
					when ('1001', '11111', '00000x', _, _) => __UNALLOCATED
					when ('1001', '11111', '000010', _, _) => __encoding aarch64_branch_unconditional_register 
					when ('1001', '11111', '000011', _, _) => __encoding aarch64_branch_unconditional_register 
					when ('1001', '11111', '0001xx', _, _) => __UNALLOCATED
					when ('1001', '11111', '001xxx', _, _) => __UNALLOCATED
					when ('1001', '11111', '01xxxx', _, _) => __UNALLOCATED
					when ('1001', '11111', '1xxxxx', _, _) => __UNALLOCATED
					when ('101x', '11111', _, _, _) => __UNALLOCATED
					when ('11xx', '11111', _, _, _) => __UNALLOCATED
			when ('x00', _, _, _, _) => 
				__field op 31 +: 1
				__field imm26 0 +: 26
				case (op) of
					when ('0') => __encoding aarch64_branch_unconditional_immediate 
					when ('1') => __encoding aarch64_branch_unconditional_immediate 
			when ('x01', _, '0xxxxxxxxxxxxx', _, _) => 
				__field sf 31 +: 1
				__field op 24 +: 1
				__field imm19 5 +: 19
				__field Rt 0 +: 5
				case (sf, op) of
					when ('0', '0') => __encoding aarch64_branch_conditional_compare 
					when ('0', '1') => __encoding aarch64_branch_conditional_compare 
					when ('1', '0') => __encoding aarch64_branch_conditional_compare 
					when ('1', '1') => __encoding aarch64_branch_conditional_compare 
			when ('x01', _, '1xxxxxxxxxxxxx', _, _) => 
				__field b5 31 +: 1
				__field op 24 +: 1
				__field b40 19 +: 5
				__field imm14 5 +: 14
				__field Rt 0 +: 5
				case (op) of
					when ('0') => __encoding aarch64_branch_conditional_test 
					when ('1') => __encoding aarch64_branch_conditional_test 
	when (_, 'x1x0x', _) =>
		case (28 +: 4, 27 +: 1, 26 +: 1, 25 +: 1, 23 +: 2, 22 +: 1, 16 +: 6, 12 +: 4, 10 +: 2, 0 +: 10) of
			when ('0x00', _, '1', _, '00', _, '000000', _, _, _) => 
				__field Q 30 +: 1
				__field L 22 +: 1
				__field opcode 12 +: 4
				__field size 10 +: 2
				__field Rn 5 +: 5
				__field Rt 0 +: 5
				case (L, opcode) of
					when ('0', '0000') => __encoding aarch64_memory_vector_multiple_no_wb 
					when ('0', '0001') => __UNALLOCATED
					when ('0', '0010') => __encoding aarch64_memory_vector_multiple_no_wb 
					when ('0', '0011') => __UNALLOCATED
					when ('0', '0100') => __encoding aarch64_memory_vector_multiple_no_wb 
					when ('0', '0101') => __UNALLOCATED
					when ('0', '0110') => __encoding aarch64_memory_vector_multiple_no_wb 
					when ('0', '0111') => __encoding aarch64_memory_vector_multiple_no_wb 
					when ('0', '1000') => __encoding aarch64_memory_vector_multiple_no_wb 
					when ('0', '1001') => __UNALLOCATED
					when ('0', '1010') => __encoding aarch64_memory_vector_multiple_no_wb 
					when ('0', '1011') => __UNALLOCATED
					when ('0', '11xx') => __UNALLOCATED
					when ('1', '0000') => __encoding aarch64_memory_vector_multiple_no_wb 
					when ('1', '0001') => __UNALLOCATED
					when ('1', '0010') => __encoding aarch64_memory_vector_multiple_no_wb 
					when ('1', '0011') => __UNALLOCATED
					when ('1', '0100') => __encoding aarch64_memory_vector_multiple_no_wb 
					when ('1', '0101') => __UNALLOCATED
					when ('1', '0110') => __encoding aarch64_memory_vector_multiple_no_wb 
					when ('1', '0111') => __encoding aarch64_memory_vector_multiple_no_wb 
					when ('1', '1000') => __encoding aarch64_memory_vector_multiple_no_wb 
					when ('1', '1001') => __UNALLOCATED
					when ('1', '1010') => __encoding aarch64_memory_vector_multiple_no_wb 
					when ('1', '1011') => __UNALLOCATED
					when ('1', '11xx') => __UNALLOCATED
			when ('0x00', _, '1', _, '01', _, '0xxxxx', _, _, _) => 
				__field Q 30 +: 1
				__field L 22 +: 1
				__field Rm 16 +: 5
				__field opcode 12 +: 4
				__field size 10 +: 2
				__field Rn 5 +: 5
				__field Rt 0 +: 5
				case (L, Rm, opcode) of
					when ('0', _, '0001') => __UNALLOCATED
					when ('0', _, '0011') => __UNALLOCATED
					when ('0', _, '0101') => __UNALLOCATED
					when ('0', _, '1001') => __UNALLOCATED
					when ('0', _, '1011') => __UNALLOCATED
					when ('0', _, '11xx') => __UNALLOCATED
					when ('0', !'11111', '0000') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('0', !'11111', '0010') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('0', !'11111', '0100') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('0', !'11111', '0110') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('0', !'11111', '0111') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('0', !'11111', '1000') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('0', !'11111', '1010') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('0', '11111', '0000') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('0', '11111', '0010') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('0', '11111', '0100') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('0', '11111', '0110') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('0', '11111', '0111') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('0', '11111', '1000') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('0', '11111', '1010') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('1', _, '0001') => __UNALLOCATED
					when ('1', _, '0011') => __UNALLOCATED
					when ('1', _, '0101') => __UNALLOCATED
					when ('1', _, '1001') => __UNALLOCATED
					when ('1', _, '1011') => __UNALLOCATED
					when ('1', _, '11xx') => __UNALLOCATED
					when ('1', !'11111', '0000') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('1', !'11111', '0010') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('1', !'11111', '0100') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('1', !'11111', '0110') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('1', !'11111', '0111') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('1', !'11111', '1000') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('1', !'11111', '1010') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('1', '11111', '0000') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('1', '11111', '0010') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('1', '11111', '0100') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('1', '11111', '0110') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('1', '11111', '0111') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('1', '11111', '1000') => __encoding aarch64_memory_vector_multiple_post_inc 
					when ('1', '11111', '1010') => __encoding aarch64_memory_vector_multiple_post_inc 
			when ('0x00', _, '1', _, '0x', _, '1xxxxx', _, _, _) => __UNPREDICTABLE
			when ('0x00', _, '1', _, '10', _, 'x00000', _, _, _) => 
				__field Q 30 +: 1
				__field L 22 +: 1
				__field R 21 +: 1
				__field opcode 13 +: 3
				__field S 12 +: 1
				__field size 10 +: 2
				__field Rn 5 +: 5
				__field Rt 0 +: 5
				case (L, R, opcode, S, size) of
					when ('0', _, '11x', _, _) => __UNALLOCATED
					when ('0', '0', '000', _, _) => __encoding aarch64_memory_vector_single_no_wb 
					when ('0', '0', '001', _, _) => __encoding aarch64_memory_vector_single_no_wb 
					when ('0', '0', '010', _, 'x0') => __encoding aarch64_memory_vector_single_no_wb 
					when ('0', '0', '010', _, 'x1') => __UNALLOCATED
					when ('0', '0', '011', _, 'x0') => __encoding aarch64_memory_vector_single_no_wb 
					when ('0', '0', '011', _, 'x1') => __UNALLOCATED
					when ('0', '0', '100', _, '00') => __encoding aarch64_memory_vector_single_no_wb 
					when ('0', '0', '100', _, '1x') => __UNALLOCATED
					when ('0', '0', '100', '0', '01') => __encoding aarch64_memory_vector_single_no_wb 
					when ('0', '0', '100', '1', '01') => __UNALLOCATED
					when ('0', '0', '101', _, '00') => __encoding aarch64_memory_vector_single_no_wb 
					when ('0', '0', '101', _, '10') => __UNALLOCATED
					when ('0', '0', '101', '0', '01') => __encoding aarch64_memory_vector_single_no_wb 
					when ('0', '0', '101', '0', '11') => __UNALLOCATED
					when ('0', '0', '101', '1', 'x1') => __UNALLOCATED
					when ('0', '1', '000', _, _) => __encoding aarch64_memory_vector_single_no_wb 
					when ('0', '1', '001', _, _) => __encoding aarch64_memory_vector_single_no_wb 
					when ('0', '1', '010', _, 'x0') => __encoding aarch64_memory_vector_single_no_wb 
					when ('0', '1', '010', _, 'x1') => __UNALLOCATED
					when ('0', '1', '011', _, 'x0') => __encoding aarch64_memory_vector_single_no_wb 
					when ('0', '1', '011', _, 'x1') => __UNALLOCATED
					when ('0', '1', '100', _, '00') => __encoding aarch64_memory_vector_single_no_wb 
					when ('0', '1', '100', _, '10') => __UNALLOCATED
					when ('0', '1', '100', '0', '01') => __encoding aarch64_memory_vector_single_no_wb 
					when ('0', '1', '100', '0', '11') => __UNALLOCATED
					when ('0', '1', '100', '1', 'x1') => __UNALLOCATED
					when ('0', '1', '101', _, '00') => __encoding aarch64_memory_vector_single_no_wb 
					when ('0', '1', '101', _, '10') => __UNALLOCATED
					when ('0', '1', '101', '0', '01') => __encoding aarch64_memory_vector_single_no_wb 
					when ('0', '1', '101', '0', '11') => __UNALLOCATED
					when ('0', '1', '101', '1', 'x1') => __UNALLOCATED
					when ('1', '0', '000', _, _) => __encoding aarch64_memory_vector_single_no_wb 
					when ('1', '0', '001', _, _) => __encoding aarch64_memory_vector_single_no_wb 
					when ('1', '0', '010', _, 'x0') => __encoding aarch64_memory_vector_single_no_wb 
					when ('1', '0', '010', _, 'x1') => __UNALLOCATED
					when ('1', '0', '011', _, 'x0') => __encoding aarch64_memory_vector_single_no_wb 
					when ('1', '0', '011', _, 'x1') => __UNALLOCATED
					when ('1', '0', '100', _, '00') => __encoding aarch64_memory_vector_single_no_wb 
					when ('1', '0', '100', _, '1x') => __UNALLOCATED
					when ('1', '0', '100', '0', '01') => __encoding aarch64_memory_vector_single_no_wb 
					when ('1', '0', '100', '1', '01') => __UNALLOCATED
					when ('1', '0', '101', _, '00') => __encoding aarch64_memory_vector_single_no_wb 
					when ('1', '0', '101', _, '10') => __UNALLOCATED
					when ('1', '0', '101', '0', '01') => __encoding aarch64_memory_vector_single_no_wb 
					when ('1', '0', '101', '0', '11') => __UNALLOCATED
					when ('1', '0', '101', '1', 'x1') => __UNALLOCATED
					when ('1', '0', '110', '0', _) => __encoding aarch64_memory_vector_single_no_wb 
					when ('1', '0', '110', '1', _) => __UNALLOCATED
					when ('1', '0', '111', '0', _) => __encoding aarch64_memory_vector_single_no_wb 
					when ('1', '0', '111', '1', _) => __UNALLOCATED
					when ('1', '1', '000', _, _) => __encoding aarch64_memory_vector_single_no_wb 
					when ('1', '1', '001', _, _) => __encoding aarch64_memory_vector_single_no_wb 
					when ('1', '1', '010', _, 'x0') => __encoding aarch64_memory_vector_single_no_wb 
					when ('1', '1', '010', _, 'x1') => __UNALLOCATED
					when ('1', '1', '011', _, 'x0') => __encoding aarch64_memory_vector_single_no_wb 
					when ('1', '1', '011', _, 'x1') => __UNALLOCATED
					when ('1', '1', '100', _, '00') => __encoding aarch64_memory_vector_single_no_wb 
					when ('1', '1', '100', _, '10') => __UNALLOCATED
					when ('1', '1', '100', '0', '01') => __encoding aarch64_memory_vector_single_no_wb 
					when ('1', '1', '100', '0', '11') => __UNALLOCATED
					when ('1', '1', '100', '1', 'x1') => __UNALLOCATED
					when ('1', '1', '101', _, '00') => __encoding aarch64_memory_vector_single_no_wb 
					when ('1', '1', '101', _, '10') => __UNALLOCATED
					when ('1', '1', '101', '0', '01') => __encoding aarch64_memory_vector_single_no_wb 
					when ('1', '1', '101', '0', '11') => __UNALLOCATED
					when ('1', '1', '101', '1', 'x1') => __UNALLOCATED
					when ('1', '1', '110', '0', _) => __encoding aarch64_memory_vector_single_no_wb 
					when ('1', '1', '110', '1', _) => __UNALLOCATED
					when ('1', '1', '111', '0', _) => __encoding aarch64_memory_vector_single_no_wb 
					when ('1', '1', '111', '1', _) => __UNALLOCATED
			when ('0x00', _, '1', _, '11', _, _, _, _, _) => 
				__field Q 30 +: 1
				__field L 22 +: 1
				__field R 21 +: 1
				__field Rm 16 +: 5
				__field opcode 13 +: 3
				__field S 12 +: 1
				__field size 10 +: 2
				__field Rn 5 +: 5
				__field Rt 0 +: 5
				case (L, R, Rm, opcode, S, size) of
					when ('0', _, _, '11x', _, _) => __UNALLOCATED
					when ('0', '0', _, '010', _, 'x1') => __UNALLOCATED
					when ('0', '0', _, '011', _, 'x1') => __UNALLOCATED
					when ('0', '0', _, '100', _, '1x') => __UNALLOCATED
					when ('0', '0', _, '100', '1', '01') => __UNALLOCATED
					when ('0', '0', _, '101', _, '10') => __UNALLOCATED
					when ('0', '0', _, '101', '0', '11') => __UNALLOCATED
					when ('0', '0', _, '101', '1', 'x1') => __UNALLOCATED
					when ('0', '0', !'11111', '000', _, _) => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '0', !'11111', '001', _, _) => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '0', !'11111', '010', _, 'x0') => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '0', !'11111', '011', _, 'x0') => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '0', !'11111', '100', _, '00') => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '0', !'11111', '100', '0', '01') => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '0', !'11111', '101', _, '00') => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '0', !'11111', '101', '0', '01') => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '0', '11111', '000', _, _) => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '0', '11111', '001', _, _) => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '0', '11111', '010', _, 'x0') => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '0', '11111', '011', _, 'x0') => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '0', '11111', '100', _, '00') => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '0', '11111', '100', '0', '01') => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '0', '11111', '101', _, '00') => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '0', '11111', '101', '0', '01') => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '1', _, '010', _, 'x1') => __UNALLOCATED
					when ('0', '1', _, '011', _, 'x1') => __UNALLOCATED
					when ('0', '1', _, '100', _, '10') => __UNALLOCATED
					when ('0', '1', _, '100', '0', '11') => __UNALLOCATED
					when ('0', '1', _, '100', '1', 'x1') => __UNALLOCATED
					when ('0', '1', _, '101', _, '10') => __UNALLOCATED
					when ('0', '1', _, '101', '0', '11') => __UNALLOCATED
					when ('0', '1', _, '101', '1', 'x1') => __UNALLOCATED
					when ('0', '1', !'11111', '000', _, _) => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '1', !'11111', '001', _, _) => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '1', !'11111', '010', _, 'x0') => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '1', !'11111', '011', _, 'x0') => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '1', !'11111', '100', _, '00') => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '1', !'11111', '100', '0', '01') => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '1', !'11111', '101', _, '00') => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '1', !'11111', '101', '0', '01') => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '1', '11111', '000', _, _) => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '1', '11111', '001', _, _) => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '1', '11111', '010', _, 'x0') => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '1', '11111', '011', _, 'x0') => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '1', '11111', '100', _, '00') => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '1', '11111', '100', '0', '01') => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '1', '11111', '101', _, '00') => __encoding aarch64_memory_vector_single_post_inc 
					when ('0', '1', '11111', '101', '0', '01') => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '0', _, '010', _, 'x1') => __UNALLOCATED
					when ('1', '0', _, '011', _, 'x1') => __UNALLOCATED
					when ('1', '0', _, '100', _, '1x') => __UNALLOCATED
					when ('1', '0', _, '100', '1', '01') => __UNALLOCATED
					when ('1', '0', _, '101', _, '10') => __UNALLOCATED
					when ('1', '0', _, '101', '0', '11') => __UNALLOCATED
					when ('1', '0', _, '101', '1', 'x1') => __UNALLOCATED
					when ('1', '0', _, '110', '1', _) => __UNALLOCATED
					when ('1', '0', _, '111', '1', _) => __UNALLOCATED
					when ('1', '0', !'11111', '000', _, _) => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '0', !'11111', '001', _, _) => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '0', !'11111', '010', _, 'x0') => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '0', !'11111', '011', _, 'x0') => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '0', !'11111', '100', _, '00') => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '0', !'11111', '100', '0', '01') => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '0', !'11111', '101', _, '00') => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '0', !'11111', '101', '0', '01') => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '0', !'11111', '110', '0', _) => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '0', !'11111', '111', '0', _) => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '0', '11111', '000', _, _) => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '0', '11111', '001', _, _) => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '0', '11111', '010', _, 'x0') => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '0', '11111', '011', _, 'x0') => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '0', '11111', '100', _, '00') => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '0', '11111', '100', '0', '01') => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '0', '11111', '101', _, '00') => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '0', '11111', '101', '0', '01') => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '0', '11111', '110', '0', _) => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '0', '11111', '111', '0', _) => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '1', _, '010', _, 'x1') => __UNALLOCATED
					when ('1', '1', _, '011', _, 'x1') => __UNALLOCATED
					when ('1', '1', _, '100', _, '10') => __UNALLOCATED
					when ('1', '1', _, '100', '0', '11') => __UNALLOCATED
					when ('1', '1', _, '100', '1', 'x1') => __UNALLOCATED
					when ('1', '1', _, '101', _, '10') => __UNALLOCATED
					when ('1', '1', _, '101', '0', '11') => __UNALLOCATED
					when ('1', '1', _, '101', '1', 'x1') => __UNALLOCATED
					when ('1', '1', _, '110', '1', _) => __UNALLOCATED
					when ('1', '1', _, '111', '1', _) => __UNALLOCATED
					when ('1', '1', !'11111', '000', _, _) => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '1', !'11111', '001', _, _) => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '1', !'11111', '010', _, 'x0') => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '1', !'11111', '011', _, 'x0') => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '1', !'11111', '100', _, '00') => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '1', !'11111', '100', '0', '01') => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '1', !'11111', '101', _, '00') => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '1', !'11111', '101', '0', '01') => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '1', !'11111', '110', '0', _) => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '1', !'11111', '111', '0', _) => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '1', '11111', '000', _, _) => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '1', '11111', '001', _, _) => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '1', '11111', '010', _, 'x0') => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '1', '11111', '011', _, 'x0') => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '1', '11111', '100', _, '00') => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '1', '11111', '100', '0', '01') => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '1', '11111', '101', _, '00') => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '1', '11111', '101', '0', '01') => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '1', '11111', '110', '0', _) => __encoding aarch64_memory_vector_single_post_inc 
					when ('1', '1', '11111', '111', '0', _) => __encoding aarch64_memory_vector_single_post_inc 
			when ('0x00', _, '1', _, 'x0', _, 'x1xxxx', _, _, _) => __UNPREDICTABLE
			when ('0x00', _, '1', _, 'x0', _, 'xx1xxx', _, _, _) => __UNPREDICTABLE
			when ('0x00', _, '1', _, 'x0', _, 'xxx1xx', _, _, _) => __UNPREDICTABLE
			when ('0x00', _, '1', _, 'x0', _, 'xxxx1x', _, _, _) => __UNPREDICTABLE
			when ('0x00', _, '1', _, 'x0', _, 'xxxxx1', _, _, _) => __UNPREDICTABLE
			when ('1101', _, '0', _, '1x', _, '1xxxxx', _, _, _) => 
				__field opc 22 +: 2
				__field imm9 12 +: 9
				__field op2 10 +: 2
				__field Rn 5 +: 5
				__field Rt 0 +: 5
				case (opc, imm9, op2) of
					when ('00', _, '01') => __encoding aarch64_integer_tags_mcsettagpost 
					when ('00', _, '10') => __encoding aarch64_integer_tags_mcsettag 
					when ('00', _, '11') => __encoding aarch64_integer_tags_mcsettagpre 
					when ('00', '000000000', '00') => __encoding aarch64_integer_tags_mcsettagandzeroarray 
					when ('01', _, '00') => __encoding aarch64_integer_tags_mcgettag 
					when ('01', _, '01') => __encoding aarch64_integer_tags_mcsettagandzerodatapost 
					when ('01', _, '10') => __encoding aarch64_integer_tags_mcsettagandzerodata 
					when ('01', _, '11') => __encoding aarch64_integer_tags_mcsettagandzerodatapre 
					when ('10', _, '01') => __encoding aarch64_integer_tags_mcsettagpairpost 
					when ('10', _, '10') => __encoding aarch64_integer_tags_mcsettagpair 
					when ('10', _, '11') => __encoding aarch64_integer_tags_mcsettagpairpre 
					when ('10', !'000000000', '00') => __UNALLOCATED
					when ('10', '000000000', '00') => __encoding aarch64_integer_tags_mcsettagarray 
					when ('11', _, '01') => __encoding aarch64_integer_tags_mcsettagpairandzerodatapost 
					when ('11', _, '10') => __encoding aarch64_integer_tags_mcsettagpairandzerodata 
					when ('11', _, '11') => __encoding aarch64_integer_tags_mcsettagpairandzerodatapre 
					when ('11', !'000000000', '00') => __UNALLOCATED
					when ('11', '000000000', '00') => __encoding aarch64_integer_tags_mcgettagarray 
			when ('1x00', _, '1', _, _, _, _, _, _, _) => __UNPREDICTABLE
			when ('xx00', _, '0', _, '0x', _, _, _, _, _) => 
				__field size 30 +: 2
				__field o2 23 +: 1
				__field L 22 +: 1
				__field o1 21 +: 1
				__field Rs 16 +: 5
				__field o0 15 +: 1
				__field Rt2 10 +: 5
				__field Rn 5 +: 5
				__field Rt 0 +: 5
				case (size, o2, L, o1, o0, Rt2) of
					when (_, '1', _, '1', _, !'11111') => __UNALLOCATED
					when ('0x', '0', _, '1', _, !'11111') => __UNALLOCATED
					when ('00', '0', '0', '0', '0', _) => __encoding aarch64_memory_exclusive_single 
					when ('00', '0', '0', '0', '1', _) => __encoding aarch64_memory_exclusive_single 
					when ('00', '0', '0', '1', '0', '11111') => __encoding aarch64_memory_atomicops_cas_pair 
					when ('00', '0', '0', '1', '1', '11111') => __encoding aarch64_memory_atomicops_cas_pair 
					when ('00', '0', '1', '0', '0', _) => __encoding aarch64_memory_exclusive_single 
					when ('00', '0', '1', '0', '1', _) => __encoding aarch64_memory_exclusive_single 
					when ('00', '0', '1', '1', '0', '11111') => __encoding aarch64_memory_atomicops_cas_pair 
					when ('00', '0', '1', '1', '1', '11111') => __encoding aarch64_memory_atomicops_cas_pair 
					when ('00', '1', '0', '0', '0', _) => __encoding aarch64_memory_ordered 
					when ('00', '1', '0', '0', '1', _) => __encoding aarch64_memory_ordered 
					when ('00', '1', '0', '1', '0', '11111') => __encoding aarch64_memory_atomicops_cas_single 
					when ('00', '1', '0', '1', '1', '11111') => __encoding aarch64_memory_atomicops_cas_single 
					when ('00', '1', '1', '0', '0', _) => __encoding aarch64_memory_ordered 
					when ('00', '1', '1', '0', '1', _) => __encoding aarch64_memory_ordered 
					when ('00', '1', '1', '1', '0', '11111') => __encoding aarch64_memory_atomicops_cas_single 
					when ('00', '1', '1', '1', '1', '11111') => __encoding aarch64_memory_atomicops_cas_single 
					when ('01', '0', '0', '0', '0', _) => __encoding aarch64_memory_exclusive_single 
					when ('01', '0', '0', '0', '1', _) => __encoding aarch64_memory_exclusive_single 
					when ('01', '0', '0', '1', '0', '11111') => __encoding aarch64_memory_atomicops_cas_pair 
					when ('01', '0', '0', '1', '1', '11111') => __encoding aarch64_memory_atomicops_cas_pair 
					when ('01', '0', '1', '0', '0', _) => __encoding aarch64_memory_exclusive_single 
					when ('01', '0', '1', '0', '1', _) => __encoding aarch64_memory_exclusive_single 
					when ('01', '0', '1', '1', '0', '11111') => __encoding aarch64_memory_atomicops_cas_pair 
					when ('01', '0', '1', '1', '1', '11111') => __encoding aarch64_memory_atomicops_cas_pair 
					when ('01', '1', '0', '0', '0', _) => __encoding aarch64_memory_ordered 
					when ('01', '1', '0', '0', '1', _) => __encoding aarch64_memory_ordered 
					when ('01', '1', '0', '1', '0', '11111') => __encoding aarch64_memory_atomicops_cas_single 
					when ('01', '1', '0', '1', '1', '11111') => __encoding aarch64_memory_atomicops_cas_single 
					when ('01', '1', '1', '0', '0', _) => __encoding aarch64_memory_ordered 
					when ('01', '1', '1', '0', '1', _) => __encoding aarch64_memory_ordered 
					when ('01', '1', '1', '1', '0', '11111') => __encoding aarch64_memory_atomicops_cas_single 
					when ('01', '1', '1', '1', '1', '11111') => __encoding aarch64_memory_atomicops_cas_single 
					when ('10', '0', '0', '0', '0', _) => __encoding aarch64_memory_exclusive_single 
					when ('10', '0', '0', '0', '1', _) => __encoding aarch64_memory_exclusive_single 
					when ('10', '0', '0', '1', '0', _) => __encoding aarch64_memory_exclusive_pair 
					when ('10', '0', '0', '1', '1', _) => __encoding aarch64_memory_exclusive_pair 
					when ('10', '0', '1', '0', '0', _) => __encoding aarch64_memory_exclusive_single 
					when ('10', '0', '1', '0', '1', _) => __encoding aarch64_memory_exclusive_single 
					when ('10', '0', '1', '1', '0', _) => __encoding aarch64_memory_exclusive_pair 
					when ('10', '0', '1', '1', '1', _) => __encoding aarch64_memory_exclusive_pair 
					when ('10', '1', '0', '0', '0', _) => __encoding aarch64_memory_ordered 
					when ('10', '1', '0', '0', '1', _) => __encoding aarch64_memory_ordered 
					when ('10', '1', '0', '1', '0', '11111') => __encoding aarch64_memory_atomicops_cas_single 
					when ('10', '1', '0', '1', '1', '11111') => __encoding aarch64_memory_atomicops_cas_single 
					when ('10', '1', '1', '0', '0', _) => __encoding aarch64_memory_ordered 
					when ('10', '1', '1', '0', '1', _) => __encoding aarch64_memory_ordered 
					when ('10', '1', '1', '1', '0', '11111') => __encoding aarch64_memory_atomicops_cas_single 
					when ('10', '1', '1', '1', '1', '11111') => __encoding aarch64_memory_atomicops_cas_single 
					when ('11', '0', '0', '0', '0', _) => __encoding aarch64_memory_exclusive_single 
					when ('11', '0', '0', '0', '1', _) => __encoding aarch64_memory_exclusive_single 
					when ('11', '0', '0', '1', '0', _) => __encoding aarch64_memory_exclusive_pair 
					when ('11', '0', '0', '1', '1', _) => __encoding aarch64_memory_exclusive_pair 
					when ('11', '0', '1', '0', '0', _) => __encoding aarch64_memory_exclusive_single 
					when ('11', '0', '1', '0', '1', _) => __encoding aarch64_memory_exclusive_single 
					when ('11', '0', '1', '1', '0', _) => __encoding aarch64_memory_exclusive_pair 
					when ('11', '0', '1', '1', '1', _) => __encoding aarch64_memory_exclusive_pair 
					when ('11', '1', '0', '0', '0', _) => __encoding aarch64_memory_ordered 
					when ('11', '1', '0', '0', '1', _) => __encoding aarch64_memory_ordered 
					when ('11', '1', '0', '1', '0', '11111') => __encoding aarch64_memory_atomicops_cas_single 
					when ('11', '1', '0', '1', '1', '11111') => __encoding aarch64_memory_atomicops_cas_single 
					when ('11', '1', '1', '0', '0', _) => __encoding aarch64_memory_ordered 
					when ('11', '1', '1', '0', '1', _) => __encoding aarch64_memory_ordered 
					when ('11', '1', '1', '1', '0', '11111') => __encoding aarch64_memory_atomicops_cas_single 
					when ('11', '1', '1', '1', '1', '11111') => __encoding aarch64_memory_atomicops_cas_single 
			when ('xx01', _, '0', _, '1x', _, '0xxxxx', _, '00', _) => 
				__field size 30 +: 2
				__field opc 22 +: 2
				__field imm9 12 +: 9
				__field Rn 5 +: 5
				__field Rt 0 +: 5
				case (size, opc) of
					when ('00', '00') => __encoding aarch64_memory_single_general_immediate_signed_offset_lda_stl 
					when ('00', '01') => __encoding aarch64_memory_single_general_immediate_signed_offset_lda_stl 
					when ('00', '10') => __encoding aarch64_memory_single_general_immediate_signed_offset_lda_stl 
					when ('00', '11') => __encoding aarch64_memory_single_general_immediate_signed_offset_lda_stl 
					when ('01', '00') => __encoding aarch64_memory_single_general_immediate_signed_offset_lda_stl 
					when ('01', '01') => __encoding aarch64_memory_single_general_immediate_signed_offset_lda_stl 
					when ('01', '10') => __encoding aarch64_memory_single_general_immediate_signed_offset_lda_stl 
					when ('01', '11') => __encoding aarch64_memory_single_general_immediate_signed_offset_lda_stl 
					when ('10', '00') => __encoding aarch64_memory_single_general_immediate_signed_offset_lda_stl 
					when ('10', '01') => __encoding aarch64_memory_single_general_immediate_signed_offset_lda_stl 
					when ('10', '10') => __encoding aarch64_memory_single_general_immediate_signed_offset_lda_stl 
					when ('10', '11') => __UNALLOCATED
					when ('11', '00') => __encoding aarch64_memory_single_general_immediate_signed_offset_lda_stl 
					when ('11', '01') => __encoding aarch64_memory_single_general_immediate_signed_offset_lda_stl 
					when ('11', '10') => __UNALLOCATED
					when ('11', '11') => __UNALLOCATED
			when ('xx01', _, _, _, '0x', _, _, _, _, _) => 
				__field opc 30 +: 2
				__field V 26 +: 1
				__field imm19 5 +: 19
				__field Rt 0 +: 5
				case (opc, V) of
					when ('00', '0') => __encoding aarch64_memory_literal_general 
					when ('00', '1') => __encoding aarch64_memory_literal_simdfp 
					when ('01', '0') => __encoding aarch64_memory_literal_general 
					when ('01', '1') => __encoding aarch64_memory_literal_simdfp 
					when ('10', '0') => __encoding aarch64_memory_literal_general 
					when ('10', '1') => __encoding aarch64_memory_literal_simdfp 
					when ('11', '0') => __encoding aarch64_memory_literal_general 
					when ('11', '1') => __UNALLOCATED
			when ('xx10', _, _, _, '00', _, _, _, _, _) => 
				__field opc 30 +: 2
				__field V 26 +: 1
				__field L 22 +: 1
				__field imm7 15 +: 7
				__field Rt2 10 +: 5
				__field Rn 5 +: 5
				__field Rt 0 +: 5
				case (opc, V, L) of
					when ('00', '0', '0') => __encoding aarch64_memory_pair_general_no_alloc 
					when ('00', '0', '1') => __encoding aarch64_memory_pair_general_no_alloc 
					when ('00', '1', '0') => __encoding aarch64_memory_pair_simdfp_no_alloc 
					when ('00', '1', '1') => __encoding aarch64_memory_pair_simdfp_no_alloc 
					when ('01', '0', _) => __UNALLOCATED
					when ('01', '1', '0') => __encoding aarch64_memory_pair_simdfp_no_alloc 
					when ('01', '1', '1') => __encoding aarch64_memory_pair_simdfp_no_alloc 
					when ('10', '0', '0') => __encoding aarch64_memory_pair_general_no_alloc 
					when ('10', '0', '1') => __encoding aarch64_memory_pair_general_no_alloc 
					when ('10', '1', '0') => __encoding aarch64_memory_pair_simdfp_no_alloc 
					when ('10', '1', '1') => __encoding aarch64_memory_pair_simdfp_no_alloc 
					when ('11', _, _) => __UNALLOCATED
			when ('xx10', _, _, _, '01', _, _, _, _, _) => 
				__field opc 30 +: 2
				__field V 26 +: 1
				__field L 22 +: 1
				__field imm7 15 +: 7
				__field Rt2 10 +: 5
				__field Rn 5 +: 5
				__field Rt 0 +: 5
				case (opc, V, L) of
					when ('00', '0', '0') => __encoding aarch64_memory_pair_general_post_idx 
					when ('00', '0', '1') => __encoding aarch64_memory_pair_general_post_idx 
					when ('00', '1', '0') => __encoding aarch64_memory_pair_simdfp_post_idx 
					when ('00', '1', '1') => __encoding aarch64_memory_pair_simdfp_post_idx 
					when ('01', '0', '0') => __encoding aarch64_integer_tags_mcsettaganddatapairpost 
					when ('01', '0', '1') => __encoding aarch64_memory_pair_general_post_idx 
					when ('01', '1', '0') => __encoding aarch64_memory_pair_simdfp_post_idx 
					when ('01', '1', '1') => __encoding aarch64_memory_pair_simdfp_post_idx 
					when ('10', '0', '0') => __encoding aarch64_memory_pair_general_post_idx 
					when ('10', '0', '1') => __encoding aarch64_memory_pair_general_post_idx 
					when ('10', '1', '0') => __encoding aarch64_memory_pair_simdfp_post_idx 
					when ('10', '1', '1') => __encoding aarch64_memory_pair_simdfp_post_idx 
					when ('11', _, _) => __UNALLOCATED
			when ('xx10', _, _, _, '10', _, _, _, _, _) => 
				__field opc 30 +: 2
				__field V 26 +: 1
				__field L 22 +: 1
				__field imm7 15 +: 7
				__field Rt2 10 +: 5
				__field Rn 5 +: 5
				__field Rt 0 +: 5
				case (opc, V, L) of
					when ('00', '0', '0') => __encoding aarch64_memory_pair_general_offset 
					when ('00', '0', '1') => __encoding aarch64_memory_pair_general_offset 
					when ('00', '1', '0') => __encoding aarch64_memory_pair_simdfp_offset 
					when ('00', '1', '1') => __encoding aarch64_memory_pair_simdfp_offset 
					when ('01', '0', '0') => __encoding aarch64_integer_tags_mcsettaganddatapair 
					when ('01', '0', '1') => __encoding aarch64_memory_pair_general_offset 
					when ('01', '1', '0') => __encoding aarch64_memory_pair_simdfp_offset 
					when ('01', '1', '1') => __encoding aarch64_memory_pair_simdfp_offset 
					when ('10', '0', '0') => __encoding aarch64_memory_pair_general_offset 
					when ('10', '0', '1') => __encoding aarch64_memory_pair_general_offset 
					when ('10', '1', '0') => __encoding aarch64_memory_pair_simdfp_offset 
					when ('10', '1', '1') => __encoding aarch64_memory_pair_simdfp_offset 
					when ('11', _, _) => __UNALLOCATED
			when ('xx10', _, _, _, '11', _, _, _, _, _) => 
				__field opc 30 +: 2
				__field V 26 +: 1
				__field L 22 +: 1
				__field imm7 15 +: 7
				__field Rt2 10 +: 5
				__field Rn 5 +: 5
				__field Rt 0 +: 5
				case (opc, V, L) of
					when ('00', '0', '0') => __encoding aarch64_memory_pair_general_pre_idx 
					when ('00', '0', '1') => __encoding aarch64_memory_pair_general_pre_idx 
					when ('00', '1', '0') => __encoding aarch64_memory_pair_simdfp_pre_idx 
					when ('00', '1', '1') => __encoding aarch64_memory_pair_simdfp_pre_idx 
					when ('01', '0', '0') => __encoding aarch64_integer_tags_mcsettaganddatapairpre 
					when ('01', '0', '1') => __encoding aarch64_memory_pair_general_pre_idx 
					when ('01', '1', '0') => __encoding aarch64_memory_pair_simdfp_pre_idx 
					when ('01', '1', '1') => __encoding aarch64_memory_pair_simdfp_pre_idx 
					when ('10', '0', '0') => __encoding aarch64_memory_pair_general_pre_idx 
					when ('10', '0', '1') => __encoding aarch64_memory_pair_general_pre_idx 
					when ('10', '1', '0') => __encoding aarch64_memory_pair_simdfp_pre_idx 
					when ('10', '1', '1') => __encoding aarch64_memory_pair_simdfp_pre_idx 
					when ('11', _, _) => __UNALLOCATED
			when ('xx11', _, _, _, '0x', _, '0xxxxx', _, '00', _) => 
				__field size 30 +: 2
				__field V 26 +: 1
				__field opc 22 +: 2
				__field imm9 12 +: 9
				__field Rn 5 +: 5
				__field Rt 0 +: 5
				case (size, V, opc) of
					when ('x1', '1', '1x') => __UNALLOCATED
					when ('00', '0', '00') => __encoding aarch64_memory_single_general_immediate_signed_offset_normal 
					when ('00', '0', '01') => __encoding aarch64_memory_single_general_immediate_signed_offset_normal 
					when ('00', '0', '10') => __encoding aarch64_memory_single_general_immediate_signed_offset_normal 
					when ('00', '0', '11') => __encoding aarch64_memory_single_general_immediate_signed_offset_normal 
					when ('00', '1', '00') => __encoding aarch64_memory_single_simdfp_immediate_signed_offset_normal 
					when ('00', '1', '01') => __encoding aarch64_memory_single_simdfp_immediate_signed_offset_normal 
					when ('00', '1', '10') => __encoding aarch64_memory_single_simdfp_immediate_signed_offset_normal 
					when ('00', '1', '11') => __encoding aarch64_memory_single_simdfp_immediate_signed_offset_normal 
					when ('01', '0', '00') => __encoding aarch64_memory_single_general_immediate_signed_offset_normal 
					when ('01', '0', '01') => __encoding aarch64_memory_single_general_immediate_signed_offset_normal 
					when ('01', '0', '10') => __encoding aarch64_memory_single_general_immediate_signed_offset_normal 
					when ('01', '0', '11') => __encoding aarch64_memory_single_general_immediate_signed_offset_normal 
					when ('01', '1', '00') => __encoding aarch64_memory_single_simdfp_immediate_signed_offset_normal 
					when ('01', '1', '01') => __encoding aarch64_memory_single_simdfp_immediate_signed_offset_normal 
					when ('1x', '0', '11') => __UNALLOCATED
					when ('1x', '1', '1x') => __UNALLOCATED
					when ('10', '0', '00') => __encoding aarch64_memory_single_general_immediate_signed_offset_normal 
					when ('10', '0', '01') => __encoding aarch64_memory_single_general_immediate_signed_offset_normal 
					when ('10', '0', '10') => __encoding aarch64_memory_single_general_immediate_signed_offset_normal 
					when ('10', '1', '00') => __encoding aarch64_memory_single_simdfp_immediate_signed_offset_normal 
					when ('10', '1', '01') => __encoding aarch64_memory_single_simdfp_immediate_signed_offset_normal 
					when ('11', '0', '00') => __encoding aarch64_memory_single_general_immediate_signed_offset_normal 
					when ('11', '0', '01') => __encoding aarch64_memory_single_general_immediate_signed_offset_normal 
					when ('11', '0', '10') => __encoding aarch64_memory_single_general_immediate_signed_offset_normal 
					when ('11', '1', '00') => __encoding aarch64_memory_single_simdfp_immediate_signed_offset_normal 
					when ('11', '1', '01') => __encoding aarch64_memory_single_simdfp_immediate_signed_offset_normal 
			when ('xx11', _, _, _, '0x', _, '0xxxxx', _, '01', _) => 
				__field size 30 +: 2
				__field V 26 +: 1
				__field opc 22 +: 2
				__field imm9 12 +: 9
				__field Rn 5 +: 5
				__field Rt 0 +: 5
				case (size, V, opc) of
					when ('x1', '1', '1x') => __UNALLOCATED
					when ('00', '0', '00') => __encoding aarch64_memory_single_general_immediate_signed_post_idx 
					when ('00', '0', '01') => __encoding aarch64_memory_single_general_immediate_signed_post_idx 
					when ('00', '0', '10') => __encoding aarch64_memory_single_general_immediate_signed_post_idx 
					when ('00', '0', '11') => __encoding aarch64_memory_single_general_immediate_signed_post_idx 
					when ('00', '1', '00') => __encoding aarch64_memory_single_simdfp_immediate_signed_post_idx 
					when ('00', '1', '01') => __encoding aarch64_memory_single_simdfp_immediate_signed_post_idx 
					when ('00', '1', '10') => __encoding aarch64_memory_single_simdfp_immediate_signed_post_idx 
					when ('00', '1', '11') => __encoding aarch64_memory_single_simdfp_immediate_signed_post_idx 
					when ('01', '0', '00') => __encoding aarch64_memory_single_general_immediate_signed_post_idx 
					when ('01', '0', '01') => __encoding aarch64_memory_single_general_immediate_signed_post_idx 
					when ('01', '0', '10') => __encoding aarch64_memory_single_general_immediate_signed_post_idx 
					when ('01', '0', '11') => __encoding aarch64_memory_single_general_immediate_signed_post_idx 
					when ('01', '1', '00') => __encoding aarch64_memory_single_simdfp_immediate_signed_post_idx 
					when ('01', '1', '01') => __encoding aarch64_memory_single_simdfp_immediate_signed_post_idx 
					when ('1x', '0', '11') => __UNALLOCATED
					when ('1x', '1', '1x') => __UNALLOCATED
					when ('10', '0', '00') => __encoding aarch64_memory_single_general_immediate_signed_post_idx 
					when ('10', '0', '01') => __encoding aarch64_memory_single_general_immediate_signed_post_idx 
					when ('10', '0', '10') => __encoding aarch64_memory_single_general_immediate_signed_post_idx 
					when ('10', '1', '00') => __encoding aarch64_memory_single_simdfp_immediate_signed_post_idx 
					when ('10', '1', '01') => __encoding aarch64_memory_single_simdfp_immediate_signed_post_idx 
					when ('11', '0', '00') => __encoding aarch64_memory_single_general_immediate_signed_post_idx 
					when ('11', '0', '01') => __encoding aarch64_memory_single_general_immediate_signed_post_idx 
					when ('11', '0', '10') => __UNALLOCATED
					when ('11', '1', '00') => __encoding aarch64_memory_single_simdfp_immediate_signed_post_idx 
					when ('11', '1', '01') => __encoding aarch64_memory_single_simdfp_immediate_signed_post_idx 
			when ('xx11', _, _, _, '0x', _, '0xxxxx', _, '10', _) => 
				__field size 30 +: 2
				__field V 26 +: 1
				__field opc 22 +: 2
				__field imm9 12 +: 9
				__field Rn 5 +: 5
				__field Rt 0 +: 5
				case (size, V, opc) of
					when (_, '1', _) => __UNALLOCATED
					when ('00', '0', '00') => __encoding aarch64_memory_single_general_immediate_signed_offset_unpriv 
					when ('00', '0', '01') => __encoding aarch64_memory_single_general_immediate_signed_offset_unpriv 
					when ('00', '0', '10') => __encoding aarch64_memory_single_general_immediate_signed_offset_unpriv 
					when ('00', '0', '11') => __encoding aarch64_memory_single_general_immediate_signed_offset_unpriv 
					when ('01', '0', '00') => __encoding aarch64_memory_single_general_immediate_signed_offset_unpriv 
					when ('01', '0', '01') => __encoding aarch64_memory_single_general_immediate_signed_offset_unpriv 
					when ('01', '0', '10') => __encoding aarch64_memory_single_general_immediate_signed_offset_unpriv 
					when ('01', '0', '11') => __encoding aarch64_memory_single_general_immediate_signed_offset_unpriv 
					when ('1x', '0', '11') => __UNALLOCATED
					when ('10', '0', '00') => __encoding aarch64_memory_single_general_immediate_signed_offset_unpriv 
					when ('10', '0', '01') => __encoding aarch64_memory_single_general_immediate_signed_offset_unpriv 
					when ('10', '0', '10') => __encoding aarch64_memory_single_general_immediate_signed_offset_unpriv 
					when ('11', '0', '00') => __encoding aarch64_memory_single_general_immediate_signed_offset_unpriv 
					when ('11', '0', '01') => __encoding aarch64_memory_single_general_immediate_signed_offset_unpriv 
					when ('11', '0', '10') => __UNALLOCATED
			when ('xx11', _, _, _, '0x', _, '0xxxxx', _, '11', _) => 
				__field size 30 +: 2
				__field V 26 +: 1
				__field opc 22 +: 2
				__field imm9 12 +: 9
				__field Rn 5 +: 5
				__field Rt 0 +: 5
				case (size, V, opc) of
					when ('x1', '1', '1x') => __UNALLOCATED
					when ('00', '0', '00') => __encoding aarch64_memory_single_general_immediate_signed_pre_idx 
					when ('00', '0', '01') => __encoding aarch64_memory_single_general_immediate_signed_pre_idx 
					when ('00', '0', '10') => __encoding aarch64_memory_single_general_immediate_signed_pre_idx 
					when ('00', '0', '11') => __encoding aarch64_memory_single_general_immediate_signed_pre_idx 
					when ('00', '1', '00') => __encoding aarch64_memory_single_simdfp_immediate_signed_pre_idx 
					when ('00', '1', '01') => __encoding aarch64_memory_single_simdfp_immediate_signed_pre_idx 
					when ('00', '1', '10') => __encoding aarch64_memory_single_simdfp_immediate_signed_pre_idx 
					when ('00', '1', '11') => __encoding aarch64_memory_single_simdfp_immediate_signed_pre_idx 
					when ('01', '0', '00') => __encoding aarch64_memory_single_general_immediate_signed_pre_idx 
					when ('01', '0', '01') => __encoding aarch64_memory_single_general_immediate_signed_pre_idx 
					when ('01', '0', '10') => __encoding aarch64_memory_single_general_immediate_signed_pre_idx 
					when ('01', '0', '11') => __encoding aarch64_memory_single_general_immediate_signed_pre_idx 
					when ('01', '1', '00') => __encoding aarch64_memory_single_simdfp_immediate_signed_pre_idx 
					when ('01', '1', '01') => __encoding aarch64_memory_single_simdfp_immediate_signed_pre_idx 
					when ('1x', '0', '11') => __UNALLOCATED
					when ('1x', '1', '1x') => __UNALLOCATED
					when ('10', '0', '00') => __encoding aarch64_memory_single_general_immediate_signed_pre_idx 
					when ('10', '0', '01') => __encoding aarch64_memory_single_general_immediate_signed_pre_idx 
					when ('10', '0', '10') => __encoding aarch64_memory_single_general_immediate_signed_pre_idx 
					when ('10', '1', '00') => __encoding aarch64_memory_single_simdfp_immediate_signed_pre_idx 
					when ('10', '1', '01') => __encoding aarch64_memory_single_simdfp_immediate_signed_pre_idx 
					when ('11', '0', '00') => __encoding aarch64_memory_single_general_immediate_signed_pre_idx 
					when ('11', '0', '01') => __encoding aarch64_memory_single_general_immediate_signed_pre_idx 
					when ('11', '0', '10') => __UNALLOCATED
					when ('11', '1', '00') => __encoding aarch64_memory_single_simdfp_immediate_signed_pre_idx 
					when ('11', '1', '01') => __encoding aarch64_memory_single_simdfp_immediate_signed_pre_idx 
			when ('xx11', _, _, _, '0x', _, '1xxxxx', _, '00', _) => 
				__field size 30 +: 2
				__field V 26 +: 1
				__field A 23 +: 1
				__field R 22 +: 1
				__field Rs 16 +: 5
				__field o3 15 +: 1
				__field opc 12 +: 3
				__field Rn 5 +: 5
				__field Rt 0 +: 5
				case (size, V, A, R, o3, opc) of
					when (_, '0', _, _, '1', '001') => __UNALLOCATED
					when (_, '0', _, _, '1', '01x') => __UNALLOCATED
					when (_, '0', _, _, '1', '101') => __UNALLOCATED
					when (_, '0', _, _, '1', '11x') => __UNALLOCATED
					when (_, '0', '0', _, '1', '100') => __UNALLOCATED
					when (_, '0', '1', '1', '1', '100') => __UNALLOCATED
					when (_, '1', _, _, _, _) => __UNALLOCATED
					when ('00', '0', '0', '0', '0', '000') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '0', '0', '0', '001') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '0', '0', '0', '010') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '0', '0', '0', '011') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '0', '0', '0', '100') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '0', '0', '0', '101') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '0', '0', '0', '110') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '0', '0', '0', '111') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '0', '0', '1', '000') => __encoding aarch64_memory_atomicops_swp 
					when ('00', '0', '0', '1', '0', '000') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '0', '1', '0', '001') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '0', '1', '0', '010') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '0', '1', '0', '011') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '0', '1', '0', '100') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '0', '1', '0', '101') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '0', '1', '0', '110') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '0', '1', '0', '111') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '0', '1', '1', '000') => __encoding aarch64_memory_atomicops_swp 
					when ('00', '0', '1', '0', '0', '000') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '1', '0', '0', '001') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '1', '0', '0', '010') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '1', '0', '0', '011') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '1', '0', '0', '100') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '1', '0', '0', '101') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '1', '0', '0', '110') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '1', '0', '0', '111') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '1', '0', '1', '000') => __encoding aarch64_memory_atomicops_swp 
					when ('00', '0', '1', '0', '1', '100') => __encoding aarch64_memory_ordered_rcpc 
					when ('00', '0', '1', '1', '0', '000') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '1', '1', '0', '001') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '1', '1', '0', '010') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '1', '1', '0', '011') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '1', '1', '0', '100') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '1', '1', '0', '101') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '1', '1', '0', '110') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '1', '1', '0', '111') => __encoding aarch64_memory_atomicops_ld 
					when ('00', '0', '1', '1', '1', '000') => __encoding aarch64_memory_atomicops_swp 
					when ('01', '0', '0', '0', '0', '000') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '0', '0', '0', '001') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '0', '0', '0', '010') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '0', '0', '0', '011') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '0', '0', '0', '100') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '0', '0', '0', '101') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '0', '0', '0', '110') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '0', '0', '0', '111') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '0', '0', '1', '000') => __encoding aarch64_memory_atomicops_swp 
					when ('01', '0', '0', '1', '0', '000') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '0', '1', '0', '001') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '0', '1', '0', '010') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '0', '1', '0', '011') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '0', '1', '0', '100') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '0', '1', '0', '101') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '0', '1', '0', '110') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '0', '1', '0', '111') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '0', '1', '1', '000') => __encoding aarch64_memory_atomicops_swp 
					when ('01', '0', '1', '0', '0', '000') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '1', '0', '0', '001') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '1', '0', '0', '010') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '1', '0', '0', '011') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '1', '0', '0', '100') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '1', '0', '0', '101') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '1', '0', '0', '110') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '1', '0', '0', '111') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '1', '0', '1', '000') => __encoding aarch64_memory_atomicops_swp 
					when ('01', '0', '1', '0', '1', '100') => __encoding aarch64_memory_ordered_rcpc 
					when ('01', '0', '1', '1', '0', '000') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '1', '1', '0', '001') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '1', '1', '0', '010') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '1', '1', '0', '011') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '1', '1', '0', '100') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '1', '1', '0', '101') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '1', '1', '0', '110') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '1', '1', '0', '111') => __encoding aarch64_memory_atomicops_ld 
					when ('01', '0', '1', '1', '1', '000') => __encoding aarch64_memory_atomicops_swp 
					when ('10', '0', '0', '0', '0', '000') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '0', '0', '0', '001') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '0', '0', '0', '010') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '0', '0', '0', '011') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '0', '0', '0', '100') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '0', '0', '0', '101') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '0', '0', '0', '110') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '0', '0', '0', '111') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '0', '0', '1', '000') => __encoding aarch64_memory_atomicops_swp 
					when ('10', '0', '0', '1', '0', '000') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '0', '1', '0', '001') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '0', '1', '0', '010') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '0', '1', '0', '011') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '0', '1', '0', '100') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '0', '1', '0', '101') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '0', '1', '0', '110') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '0', '1', '0', '111') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '0', '1', '1', '000') => __encoding aarch64_memory_atomicops_swp 
					when ('10', '0', '1', '0', '0', '000') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '1', '0', '0', '001') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '1', '0', '0', '010') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '1', '0', '0', '011') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '1', '0', '0', '100') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '1', '0', '0', '101') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '1', '0', '0', '110') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '1', '0', '0', '111') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '1', '0', '1', '000') => __encoding aarch64_memory_atomicops_swp 
					when ('10', '0', '1', '0', '1', '100') => __encoding aarch64_memory_ordered_rcpc 
					when ('10', '0', '1', '1', '0', '000') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '1', '1', '0', '001') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '1', '1', '0', '010') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '1', '1', '0', '011') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '1', '1', '0', '100') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '1', '1', '0', '101') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '1', '1', '0', '110') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '1', '1', '0', '111') => __encoding aarch64_memory_atomicops_ld 
					when ('10', '0', '1', '1', '1', '000') => __encoding aarch64_memory_atomicops_swp 
					when ('11', '0', '0', '0', '0', '000') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '0', '0', '0', '001') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '0', '0', '0', '010') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '0', '0', '0', '011') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '0', '0', '0', '100') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '0', '0', '0', '101') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '0', '0', '0', '110') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '0', '0', '0', '111') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '0', '0', '1', '000') => __encoding aarch64_memory_atomicops_swp 
					when ('11', '0', '0', '1', '0', '000') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '0', '1', '0', '001') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '0', '1', '0', '010') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '0', '1', '0', '011') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '0', '1', '0', '100') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '0', '1', '0', '101') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '0', '1', '0', '110') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '0', '1', '0', '111') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '0', '1', '1', '000') => __encoding aarch64_memory_atomicops_swp 
					when ('11', '0', '1', '0', '0', '000') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '1', '0', '0', '001') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '1', '0', '0', '010') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '1', '0', '0', '011') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '1', '0', '0', '100') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '1', '0', '0', '101') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '1', '0', '0', '110') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '1', '0', '0', '111') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '1', '0', '1', '000') => __encoding aarch64_memory_atomicops_swp 
					when ('11', '0', '1', '0', '1', '100') => __encoding aarch64_memory_ordered_rcpc 
					when ('11', '0', '1', '1', '0', '000') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '1', '1', '0', '001') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '1', '1', '0', '010') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '1', '1', '0', '011') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '1', '1', '0', '100') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '1', '1', '0', '101') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '1', '1', '0', '110') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '1', '1', '0', '111') => __encoding aarch64_memory_atomicops_ld 
					when ('11', '0', '1', '1', '1', '000') => __encoding aarch64_memory_atomicops_swp 
			when ('xx11', _, _, _, '0x', _, '1xxxxx', _, '10', _) => 
				__field size 30 +: 2
				__field V 26 +: 1
				__field opc 22 +: 2
				__field Rm 16 +: 5
				__field option 13 +: 3
				__field S 12 +: 1
				__field Rn 5 +: 5
				__field Rt 0 +: 5
				case (size, V, opc, option) of
					when (_, _, _, 'x0x') => __UNALLOCATED
					when ('x1', '1', '1x', _) => __UNALLOCATED
					when ('00', '0', '00', !'011') => __encoding aarch64_memory_single_general_register 
					when ('00', '0', '00', '011') => __encoding aarch64_memory_single_general_register 
					when ('00', '0', '01', !'011') => __encoding aarch64_memory_single_general_register 
					when ('00', '0', '01', '011') => __encoding aarch64_memory_single_general_register 
					when ('00', '0', '10', !'011') => __encoding aarch64_memory_single_general_register 
					when ('00', '0', '10', '011') => __encoding aarch64_memory_single_general_register 
					when ('00', '0', '11', !'011') => __encoding aarch64_memory_single_general_register 
					when ('00', '0', '11', '011') => __encoding aarch64_memory_single_general_register 
					when ('00', '1', '00', !'011') => __encoding aarch64_memory_single_simdfp_register 
					when ('00', '1', '00', '011') => __encoding aarch64_memory_single_simdfp_register 
					when ('00', '1', '01', !'011') => __encoding aarch64_memory_single_simdfp_register 
					when ('00', '1', '01', '011') => __encoding aarch64_memory_single_simdfp_register 
					when ('00', '1', '10', _) => __encoding aarch64_memory_single_simdfp_register 
					when ('00', '1', '11', _) => __encoding aarch64_memory_single_simdfp_register 
					when ('01', '0', '00', _) => __encoding aarch64_memory_single_general_register 
					when ('01', '0', '01', _) => __encoding aarch64_memory_single_general_register 
					when ('01', '0', '10', _) => __encoding aarch64_memory_single_general_register 
					when ('01', '0', '11', _) => __encoding aarch64_memory_single_general_register 
					when ('01', '1', '00', _) => __encoding aarch64_memory_single_simdfp_register 
					when ('01', '1', '01', _) => __encoding aarch64_memory_single_simdfp_register 
					when ('1x', '0', '11', _) => __UNALLOCATED
					when ('1x', '1', '1x', _) => __UNALLOCATED
					when ('10', '0', '00', _) => __encoding aarch64_memory_single_general_register 
					when ('10', '0', '01', _) => __encoding aarch64_memory_single_general_register 
					when ('10', '0', '10', _) => __encoding aarch64_memory_single_general_register 
					when ('10', '1', '00', _) => __encoding aarch64_memory_single_simdfp_register 
					when ('10', '1', '01', _) => __encoding aarch64_memory_single_simdfp_register 
					when ('11', '0', '00', _) => __encoding aarch64_memory_single_general_register 
					when ('11', '0', '01', _) => __encoding aarch64_memory_single_general_register 
					when ('11', '0', '10', _) => __encoding aarch64_memory_single_general_register 
					when ('11', '1', '00', _) => __encoding aarch64_memory_single_simdfp_register 
					when ('11', '1', '01', _) => __encoding aarch64_memory_single_simdfp_register 
			when ('xx11', _, _, _, '0x', _, '1xxxxx', _, 'x1', _) => 
				__field size 30 +: 2
				__field V 26 +: 1
				__field M 23 +: 1
				__field S 22 +: 1
				__field imm9 12 +: 9
				__field W 11 +: 1
				__field Rn 5 +: 5
				__field Rt 0 +: 5
				case (size, V, M, W) of
					when (!'11', _, _, _) => __UNALLOCATED
					when ('11', '0', '0', '0') => __encoding aarch64_memory_single_general_immediate_signed_pac 
					when ('11', '0', '0', '1') => __encoding aarch64_memory_single_general_immediate_signed_pac 
					when ('11', '0', '1', '0') => __encoding aarch64_memory_single_general_immediate_signed_pac 
					when ('11', '0', '1', '1') => __encoding aarch64_memory_single_general_immediate_signed_pac 
					when ('11', '1', _, _) => __UNALLOCATED
			when ('xx11', _, _, _, '1x', _, _, _, _, _) => 
				__field size 30 +: 2
				__field V 26 +: 1
				__field opc 22 +: 2
				__field imm12 10 +: 12
				__field Rn 5 +: 5
				__field Rt 0 +: 5
				case (size, V, opc) of
					when ('x1', '1', '1x') => __UNALLOCATED
					when ('00', '0', '00') => __encoding aarch64_memory_single_general_immediate_unsigned 
					when ('00', '0', '01') => __encoding aarch64_memory_single_general_immediate_unsigned 
					when ('00', '0', '10') => __encoding aarch64_memory_single_general_immediate_unsigned 
					when ('00', '0', '11') => __encoding aarch64_memory_single_general_immediate_unsigned 
					when ('00', '1', '00') => __encoding aarch64_memory_single_simdfp_immediate_unsigned 
					when ('00', '1', '01') => __encoding aarch64_memory_single_simdfp_immediate_unsigned 
					when ('00', '1', '10') => __encoding aarch64_memory_single_simdfp_immediate_unsigned 
					when ('00', '1', '11') => __encoding aarch64_memory_single_simdfp_immediate_unsigned 
					when ('01', '0', '00') => __encoding aarch64_memory_single_general_immediate_unsigned 
					when ('01', '0', '01') => __encoding aarch64_memory_single_general_immediate_unsigned 
					when ('01', '0', '10') => __encoding aarch64_memory_single_general_immediate_unsigned 
					when ('01', '0', '11') => __encoding aarch64_memory_single_general_immediate_unsigned 
					when ('01', '1', '00') => __encoding aarch64_memory_single_simdfp_immediate_unsigned 
					when ('01', '1', '01') => __encoding aarch64_memory_single_simdfp_immediate_unsigned 
					when ('1x', '0', '11') => __UNALLOCATED
					when ('1x', '1', '1x') => __UNALLOCATED
					when ('10', '0', '00') => __encoding aarch64_memory_single_general_immediate_unsigned 
					when ('10', '0', '01') => __encoding aarch64_memory_single_general_immediate_unsigned 
					when ('10', '0', '10') => __encoding aarch64_memory_single_general_immediate_unsigned 
					when ('10', '1', '00') => __encoding aarch64_memory_single_simdfp_immediate_unsigned 
					when ('10', '1', '01') => __encoding aarch64_memory_single_simdfp_immediate_unsigned 
					when ('11', '0', '00') => __encoding aarch64_memory_single_general_immediate_unsigned 
					when ('11', '0', '01') => __encoding aarch64_memory_single_general_immediate_unsigned 
					when ('11', '0', '10') => __encoding aarch64_memory_single_general_immediate_unsigned 
					when ('11', '1', '00') => __encoding aarch64_memory_single_simdfp_immediate_unsigned 
					when ('11', '1', '01') => __encoding aarch64_memory_single_simdfp_immediate_unsigned 
	when (_, 'x101x', _) =>
		case (31 +: 1, 30 +: 1, 29 +: 1, 28 +: 1, 25 +: 3, 21 +: 4, 16 +: 5, 10 +: 6, 0 +: 10) of
			when (_, '0', _, '1', _, '0110', _, _, _) => 
				__field sf 31 +: 1
				__field S 29 +: 1
				__field Rm 16 +: 5
				__field opcode 10 +: 6
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (sf, S, opcode) of
					when (_, _, '000001') => __UNALLOCATED
					when (_, _, '011xxx') => __UNALLOCATED
					when (_, _, '1xxxxx') => __UNALLOCATED
					when (_, '0', '00011x') => __UNALLOCATED
					when (_, '0', '001101') => __UNALLOCATED
					when (_, '0', '00111x') => __UNALLOCATED
					when (_, '1', '00001x') => __UNALLOCATED
					when (_, '1', '0001xx') => __UNALLOCATED
					when (_, '1', '001xxx') => __UNALLOCATED
					when (_, '1', '01xxxx') => __UNALLOCATED
					when ('0', _, '000000') => __UNALLOCATED
					when ('0', '0', '000010') => __encoding aarch64_integer_arithmetic_div 
					when ('0', '0', '000011') => __encoding aarch64_integer_arithmetic_div 
					when ('0', '0', '00010x') => __UNALLOCATED
					when ('0', '0', '001000') => __encoding aarch64_integer_shift_variable 
					when ('0', '0', '001001') => __encoding aarch64_integer_shift_variable 
					when ('0', '0', '001010') => __encoding aarch64_integer_shift_variable 
					when ('0', '0', '001011') => __encoding aarch64_integer_shift_variable 
					when ('0', '0', '001100') => __UNALLOCATED
					when ('0', '0', '010x11') => __UNALLOCATED
					when ('0', '0', '010000') => __encoding aarch64_integer_crc 
					when ('0', '0', '010001') => __encoding aarch64_integer_crc 
					when ('0', '0', '010010') => __encoding aarch64_integer_crc 
					when ('0', '0', '010100') => __encoding aarch64_integer_crc 
					when ('0', '0', '010101') => __encoding aarch64_integer_crc 
					when ('0', '0', '010110') => __encoding aarch64_integer_crc 
					when ('1', '0', '000000') => __encoding aarch64_integer_arithmetic_pointer_mcsubtracttaggedaddress 
					when ('1', '0', '000010') => __encoding aarch64_integer_arithmetic_div 
					when ('1', '0', '000011') => __encoding aarch64_integer_arithmetic_div 
					when ('1', '0', '000100') => __encoding aarch64_integer_tags_mcinsertrandomtag 
					when ('1', '0', '000101') => __encoding aarch64_integer_tags_mcinserttagmask 
					when ('1', '0', '001000') => __encoding aarch64_integer_shift_variable 
					when ('1', '0', '001001') => __encoding aarch64_integer_shift_variable 
					when ('1', '0', '001010') => __encoding aarch64_integer_shift_variable 
					when ('1', '0', '001011') => __encoding aarch64_integer_shift_variable 
					when ('1', '0', '001100') => __encoding aarch64_integer_pac_pacga_dp_2src 
					when ('1', '0', '010xx0') => __UNALLOCATED
					when ('1', '0', '010x0x') => __UNALLOCATED
					when ('1', '0', '010011') => __encoding aarch64_integer_crc 
					when ('1', '0', '010111') => __encoding aarch64_integer_crc 
					when ('1', '1', '000000') => __encoding aarch64_integer_arithmetic_pointer_mcsubtracttaggedaddresssetflags 
			when (_, '1', _, '1', _, '0110', _, _, _) => 
				__field sf 31 +: 1
				__field S 29 +: 1
				__field opcode2 16 +: 5
				__field opcode 10 +: 6
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (sf, S, opcode2, opcode, Rn) of
					when (_, _, _, '1xxxxx', _) => __UNALLOCATED
					when (_, _, 'xxx1x', _, _) => __UNALLOCATED
					when (_, _, 'xx1xx', _, _) => __UNALLOCATED
					when (_, _, 'x1xxx', _, _) => __UNALLOCATED
					when (_, _, '1xxxx', _, _) => __UNALLOCATED
					when (_, '0', '00000', '00011x', _) => __UNALLOCATED
					when (_, '0', '00000', '001xxx', _) => __UNALLOCATED
					when (_, '0', '00000', '01xxxx', _) => __UNALLOCATED
					when (_, '1', _, _, _) => __UNALLOCATED
					when ('0', _, '00001', _, _) => __UNALLOCATED
					when ('0', '0', '00000', '000000', _) => __encoding aarch64_integer_arithmetic_rbit 
					when ('0', '0', '00000', '000001', _) => __encoding aarch64_integer_arithmetic_rev 
					when ('0', '0', '00000', '000010', _) => __encoding aarch64_integer_arithmetic_rev 
					when ('0', '0', '00000', '000011', _) => __UNALLOCATED
					when ('0', '0', '00000', '000100', _) => __encoding aarch64_integer_arithmetic_cnt 
					when ('0', '0', '00000', '000101', _) => __encoding aarch64_integer_arithmetic_cnt 
					when ('1', '0', '00000', '000000', _) => __encoding aarch64_integer_arithmetic_rbit 
					when ('1', '0', '00000', '000001', _) => __encoding aarch64_integer_arithmetic_rev 
					when ('1', '0', '00000', '000010', _) => __encoding aarch64_integer_arithmetic_rev 
					when ('1', '0', '00000', '000011', _) => __encoding aarch64_integer_arithmetic_rev 
					when ('1', '0', '00000', '000100', _) => __encoding aarch64_integer_arithmetic_cnt 
					when ('1', '0', '00000', '000101', _) => __encoding aarch64_integer_arithmetic_cnt 
					when ('1', '0', '00001', '000000', _) => __encoding aarch64_integer_pac_pacia_dp_1src 
					when ('1', '0', '00001', '000001', _) => __encoding aarch64_integer_pac_pacib_dp_1src 
					when ('1', '0', '00001', '000010', _) => __encoding aarch64_integer_pac_pacda_dp_1src 
					when ('1', '0', '00001', '000011', _) => __encoding aarch64_integer_pac_pacdb_dp_1src 
					when ('1', '0', '00001', '000100', _) => __encoding aarch64_integer_pac_autia_dp_1src 
					when ('1', '0', '00001', '000101', _) => __encoding aarch64_integer_pac_autib_dp_1src 
					when ('1', '0', '00001', '000110', _) => __encoding aarch64_integer_pac_autda_dp_1src 
					when ('1', '0', '00001', '000111', _) => __encoding aarch64_integer_pac_autdb_dp_1src 
					when ('1', '0', '00001', '001000', '11111') => __encoding aarch64_integer_pac_pacia_dp_1src 
					when ('1', '0', '00001', '001001', '11111') => __encoding aarch64_integer_pac_pacib_dp_1src 
					when ('1', '0', '00001', '001010', '11111') => __encoding aarch64_integer_pac_pacda_dp_1src 
					when ('1', '0', '00001', '001011', '11111') => __encoding aarch64_integer_pac_pacdb_dp_1src 
					when ('1', '0', '00001', '001100', '11111') => __encoding aarch64_integer_pac_autia_dp_1src 
					when ('1', '0', '00001', '001101', '11111') => __encoding aarch64_integer_pac_autib_dp_1src 
					when ('1', '0', '00001', '001110', '11111') => __encoding aarch64_integer_pac_autda_dp_1src 
					when ('1', '0', '00001', '001111', '11111') => __encoding aarch64_integer_pac_autdb_dp_1src 
					when ('1', '0', '00001', '010000', '11111') => __encoding aarch64_integer_pac_strip_dp_1src 
					when ('1', '0', '00001', '010001', '11111') => __encoding aarch64_integer_pac_strip_dp_1src 
					when ('1', '0', '00001', '01001x', _) => __UNALLOCATED
					when ('1', '0', '00001', '0101xx', _) => __UNALLOCATED
					when ('1', '0', '00001', '011xxx', _) => __UNALLOCATED
			when (_, _, _, '0', _, '0xxx', _, _, _) => 
				__field sf 31 +: 1
				__field opc 29 +: 2
				__field shift 22 +: 2
				__field N 21 +: 1
				__field Rm 16 +: 5
				__field imm6 10 +: 6
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (sf, opc, N, imm6) of
					when ('0', _, _, '1xxxxx') => __UNALLOCATED
					when ('0', '00', '0', _) => __encoding aarch64_integer_logical_shiftedreg 
					when ('0', '00', '1', _) => __encoding aarch64_integer_logical_shiftedreg 
					when ('0', '01', '0', _) => __encoding aarch64_integer_logical_shiftedreg 
					when ('0', '01', '1', _) => __encoding aarch64_integer_logical_shiftedreg 
					when ('0', '10', '0', _) => __encoding aarch64_integer_logical_shiftedreg 
					when ('0', '10', '1', _) => __encoding aarch64_integer_logical_shiftedreg 
					when ('0', '11', '0', _) => __encoding aarch64_integer_logical_shiftedreg 
					when ('0', '11', '1', _) => __encoding aarch64_integer_logical_shiftedreg 
					when ('1', '00', '0', _) => __encoding aarch64_integer_logical_shiftedreg 
					when ('1', '00', '1', _) => __encoding aarch64_integer_logical_shiftedreg 
					when ('1', '01', '0', _) => __encoding aarch64_integer_logical_shiftedreg 
					when ('1', '01', '1', _) => __encoding aarch64_integer_logical_shiftedreg 
					when ('1', '10', '0', _) => __encoding aarch64_integer_logical_shiftedreg 
					when ('1', '10', '1', _) => __encoding aarch64_integer_logical_shiftedreg 
					when ('1', '11', '0', _) => __encoding aarch64_integer_logical_shiftedreg 
					when ('1', '11', '1', _) => __encoding aarch64_integer_logical_shiftedreg 
			when (_, _, _, '0', _, '1xx0', _, _, _) => 
				__field sf 31 +: 1
				__field op 30 +: 1
				__field S 29 +: 1
				__field shift 22 +: 2
				__field Rm 16 +: 5
				__field imm6 10 +: 6
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (sf, op, S, shift, imm6) of
					when (_, _, _, '11', _) => __UNALLOCATED
					when ('0', _, _, _, '1xxxxx') => __UNALLOCATED
					when ('0', '0', '0', _, _) => __encoding aarch64_integer_arithmetic_add_sub_shiftedreg 
					when ('0', '0', '1', _, _) => __encoding aarch64_integer_arithmetic_add_sub_shiftedreg 
					when ('0', '1', '0', _, _) => __encoding aarch64_integer_arithmetic_add_sub_shiftedreg 
					when ('0', '1', '1', _, _) => __encoding aarch64_integer_arithmetic_add_sub_shiftedreg 
					when ('1', '0', '0', _, _) => __encoding aarch64_integer_arithmetic_add_sub_shiftedreg 
					when ('1', '0', '1', _, _) => __encoding aarch64_integer_arithmetic_add_sub_shiftedreg 
					when ('1', '1', '0', _, _) => __encoding aarch64_integer_arithmetic_add_sub_shiftedreg 
					when ('1', '1', '1', _, _) => __encoding aarch64_integer_arithmetic_add_sub_shiftedreg 
			when (_, _, _, '0', _, '1xx1', _, _, _) => 
				__field sf 31 +: 1
				__field op 30 +: 1
				__field S 29 +: 1
				__field opt 22 +: 2
				__field Rm 16 +: 5
				__field option 13 +: 3
				__field imm3 10 +: 3
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (sf, op, S, opt, imm3) of
					when (_, _, _, _, '1x1') => __UNALLOCATED
					when (_, _, _, _, '11x') => __UNALLOCATED
					when (_, _, _, 'x1', _) => __UNALLOCATED
					when (_, _, _, '1x', _) => __UNALLOCATED
					when ('0', '0', '0', '00', _) => __encoding aarch64_integer_arithmetic_add_sub_extendedreg 
					when ('0', '0', '1', '00', _) => __encoding aarch64_integer_arithmetic_add_sub_extendedreg 
					when ('0', '1', '0', '00', _) => __encoding aarch64_integer_arithmetic_add_sub_extendedreg 
					when ('0', '1', '1', '00', _) => __encoding aarch64_integer_arithmetic_add_sub_extendedreg 
					when ('1', '0', '0', '00', _) => __encoding aarch64_integer_arithmetic_add_sub_extendedreg 
					when ('1', '0', '1', '00', _) => __encoding aarch64_integer_arithmetic_add_sub_extendedreg 
					when ('1', '1', '0', '00', _) => __encoding aarch64_integer_arithmetic_add_sub_extendedreg 
					when ('1', '1', '1', '00', _) => __encoding aarch64_integer_arithmetic_add_sub_extendedreg 
			when (_, _, _, '1', _, '0000', _, '000000', _) => 
				__field sf 31 +: 1
				__field op 30 +: 1
				__field S 29 +: 1
				__field Rm 16 +: 5
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (sf, op, S) of
					when ('0', '0', '0') => __encoding aarch64_integer_arithmetic_add_sub_carry 
					when ('0', '0', '1') => __encoding aarch64_integer_arithmetic_add_sub_carry 
					when ('0', '1', '0') => __encoding aarch64_integer_arithmetic_add_sub_carry 
					when ('0', '1', '1') => __encoding aarch64_integer_arithmetic_add_sub_carry 
					when ('1', '0', '0') => __encoding aarch64_integer_arithmetic_add_sub_carry 
					when ('1', '0', '1') => __encoding aarch64_integer_arithmetic_add_sub_carry 
					when ('1', '1', '0') => __encoding aarch64_integer_arithmetic_add_sub_carry 
					when ('1', '1', '1') => __encoding aarch64_integer_arithmetic_add_sub_carry 
			when (_, _, _, '1', _, '0000', _, 'x00001', _) => 
				__field sf 31 +: 1
				__field op 30 +: 1
				__field S 29 +: 1
				__field imm6 15 +: 6
				__field Rn 5 +: 5
				__field o2 4 +: 1
				__field mask 0 +: 4
				case (sf, op, S, o2) of
					when ('0', _, _, _) => __UNALLOCATED
					when ('1', '0', '0', _) => __UNALLOCATED
					when ('1', '0', '1', '0') => __encoding aarch64_integer_flags_rmif 
					when ('1', '0', '1', '1') => __UNALLOCATED
					when ('1', '1', _, _) => __UNALLOCATED
			when (_, _, _, '1', _, '0000', _, 'xx0010', _) => 
				__field sf 31 +: 1
				__field op 30 +: 1
				__field S 29 +: 1
				__field opcode2 15 +: 6
				__field sz 14 +: 1
				__field Rn 5 +: 5
				__field o3 4 +: 1
				__field mask 0 +: 4
				case (sf, op, S, opcode2, sz, o3, mask) of
					when ('0', '0', '0', _, _, _, _) => __UNALLOCATED
					when ('0', '0', '1', !'000000', _, _, _) => __UNALLOCATED
					when ('0', '0', '1', '000000', _, '0', !'1101') => __UNALLOCATED
					when ('0', '0', '1', '000000', _, '1', _) => __UNALLOCATED
					when ('0', '0', '1', '000000', '0', '0', '1101') => __encoding aarch64_integer_flags_setf 
					when ('0', '0', '1', '000000', '1', '0', '1101') => __encoding aarch64_integer_flags_setf 
					when ('0', '1', _, _, _, _, _) => __UNALLOCATED
					when ('1', _, _, _, _, _, _) => __UNALLOCATED
			when (_, _, _, '1', _, '0010', _, 'xxxx0x', _) => 
				__field sf 31 +: 1
				__field op 30 +: 1
				__field S 29 +: 1
				__field Rm 16 +: 5
				__field cond 12 +: 4
				__field o2 10 +: 1
				__field Rn 5 +: 5
				__field o3 4 +: 1
				__field nzcv 0 +: 4
				case (sf, op, S, o2, o3) of
					when (_, _, _, _, '1') => __UNALLOCATED
					when (_, _, _, '1', _) => __UNALLOCATED
					when (_, _, '0', _, _) => __UNALLOCATED
					when ('0', '0', '1', '0', '0') => __encoding aarch64_integer_conditional_compare_register 
					when ('0', '1', '1', '0', '0') => __encoding aarch64_integer_conditional_compare_register 
					when ('1', '0', '1', '0', '0') => __encoding aarch64_integer_conditional_compare_register 
					when ('1', '1', '1', '0', '0') => __encoding aarch64_integer_conditional_compare_register 
			when (_, _, _, '1', _, '0010', _, 'xxxx1x', _) => 
				__field sf 31 +: 1
				__field op 30 +: 1
				__field S 29 +: 1
				__field imm5 16 +: 5
				__field cond 12 +: 4
				__field o2 10 +: 1
				__field Rn 5 +: 5
				__field o3 4 +: 1
				__field nzcv 0 +: 4
				case (sf, op, S, o2, o3) of
					when (_, _, _, _, '1') => __UNALLOCATED
					when (_, _, _, '1', _) => __UNALLOCATED
					when (_, _, '0', _, _) => __UNALLOCATED
					when ('0', '0', '1', '0', '0') => __encoding aarch64_integer_conditional_compare_immediate 
					when ('0', '1', '1', '0', '0') => __encoding aarch64_integer_conditional_compare_immediate 
					when ('1', '0', '1', '0', '0') => __encoding aarch64_integer_conditional_compare_immediate 
					when ('1', '1', '1', '0', '0') => __encoding aarch64_integer_conditional_compare_immediate 
			when (_, _, _, '1', _, '0100', _, _, _) => 
				__field sf 31 +: 1
				__field op 30 +: 1
				__field S 29 +: 1
				__field Rm 16 +: 5
				__field cond 12 +: 4
				__field op2 10 +: 2
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (sf, op, S, op2) of
					when (_, _, _, '1x') => __UNALLOCATED
					when (_, _, '1', _) => __UNALLOCATED
					when ('0', '0', '0', '00') => __encoding aarch64_integer_conditional_select 
					when ('0', '0', '0', '01') => __encoding aarch64_integer_conditional_select 
					when ('0', '1', '0', '00') => __encoding aarch64_integer_conditional_select 
					when ('0', '1', '0', '01') => __encoding aarch64_integer_conditional_select 
					when ('1', '0', '0', '00') => __encoding aarch64_integer_conditional_select 
					when ('1', '0', '0', '01') => __encoding aarch64_integer_conditional_select 
					when ('1', '1', '0', '00') => __encoding aarch64_integer_conditional_select 
					when ('1', '1', '0', '01') => __encoding aarch64_integer_conditional_select 
			when (_, _, _, '1', _, '1xxx', _, _, _) => 
				__field sf 31 +: 1
				__field op54 29 +: 2
				__field op31 21 +: 3
				__field Rm 16 +: 5
				__field o0 15 +: 1
				__field Ra 10 +: 5
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (sf, op54, op31, o0) of
					when (_, '00', '010', '1') => __UNALLOCATED
					when (_, '00', '011', _) => __UNALLOCATED
					when (_, '00', '100', _) => __UNALLOCATED
					when (_, '00', '110', '1') => __UNALLOCATED
					when (_, '00', '111', _) => __UNALLOCATED
					when (_, '01', _, _) => __UNALLOCATED
					when (_, '1x', _, _) => __UNALLOCATED
					when ('0', '00', '000', '0') => __encoding aarch64_integer_arithmetic_mul_uniform_add_sub 
					when ('0', '00', '000', '1') => __encoding aarch64_integer_arithmetic_mul_uniform_add_sub 
					when ('0', '00', '001', '0') => __UNALLOCATED
					when ('0', '00', '001', '1') => __UNALLOCATED
					when ('0', '00', '010', '0') => __UNALLOCATED
					when ('0', '00', '101', '0') => __UNALLOCATED
					when ('0', '00', '101', '1') => __UNALLOCATED
					when ('0', '00', '110', '0') => __UNALLOCATED
					when ('1', '00', '000', '0') => __encoding aarch64_integer_arithmetic_mul_uniform_add_sub 
					when ('1', '00', '000', '1') => __encoding aarch64_integer_arithmetic_mul_uniform_add_sub 
					when ('1', '00', '001', '0') => __encoding aarch64_integer_arithmetic_mul_widening_32_64 
					when ('1', '00', '001', '1') => __encoding aarch64_integer_arithmetic_mul_widening_32_64 
					when ('1', '00', '010', '0') => __encoding aarch64_integer_arithmetic_mul_widening_64_128hi 
					when ('1', '00', '101', '0') => __encoding aarch64_integer_arithmetic_mul_widening_32_64 
					when ('1', '00', '101', '1') => __encoding aarch64_integer_arithmetic_mul_widening_32_64 
					when ('1', '00', '110', '0') => __encoding aarch64_integer_arithmetic_mul_widening_64_128hi 
	when (_, 'x111x', _) =>
		case (28 +: 4, 25 +: 3, 23 +: 2, 19 +: 4, 10 +: 9, 0 +: 10) of
			when ('0000', _, '0x', 'x101', '00xxxxx10', _) => __UNPREDICTABLE
			when ('0010', _, '0x', 'x101', '00xxxxx10', _) => __UNPREDICTABLE
			when ('0100', _, '0x', 'x101', '00xxxxx10', _) => 
				__field size 22 +: 2
				__field opcode 12 +: 5
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (size, opcode) of
					when (_, 'x1xxx') => __UNALLOCATED
					when (_, '000xx') => __UNALLOCATED
					when (_, '1xxxx') => __UNALLOCATED
					when ('x1', _) => __UNALLOCATED
					when ('00', '00100') => __encoding aarch64_vector_crypto_aes_round 
					when ('00', '00101') => __encoding aarch64_vector_crypto_aes_round 
					when ('00', '00110') => __encoding aarch64_vector_crypto_aes_mix 
					when ('00', '00111') => __encoding aarch64_vector_crypto_aes_mix 
					when ('1x', _) => __UNALLOCATED
			when ('0101', _, '0x', 'x0xx', 'xxx0xxx00', _) => 
				__field size 22 +: 2
				__field Rm 16 +: 5
				__field opcode 12 +: 3
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (size, opcode) of
					when (_, '111') => __UNALLOCATED
					when ('x1', _) => __UNALLOCATED
					when ('00', '000') => __encoding aarch64_vector_crypto_sha3op_sha1_hash_choose 
					when ('00', '001') => __encoding aarch64_vector_crypto_sha3op_sha1_hash_parity 
					when ('00', '010') => __encoding aarch64_vector_crypto_sha3op_sha1_hash_majority 
					when ('00', '011') => __encoding aarch64_vector_crypto_sha3op_sha1_sched0 
					when ('00', '100') => __encoding aarch64_vector_crypto_sha3op_sha256_hash 
					when ('00', '101') => __encoding aarch64_vector_crypto_sha3op_sha256_hash 
					when ('00', '110') => __encoding aarch64_vector_crypto_sha3op_sha256_sched1 
					when ('1x', _) => __UNALLOCATED
			when ('0101', _, '0x', 'x0xx', 'xxx0xxx10', _) => __UNPREDICTABLE
			when ('0101', _, '0x', 'x101', '00xxxxx10', _) => 
				__field size 22 +: 2
				__field opcode 12 +: 5
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (size, opcode) of
					when (_, 'xx1xx') => __UNALLOCATED
					when (_, 'x1xxx') => __UNALLOCATED
					when (_, '1xxxx') => __UNALLOCATED
					when ('x1', _) => __UNALLOCATED
					when ('00', '00000') => __encoding aarch64_vector_crypto_sha2op_sha1_hash 
					when ('00', '00001') => __encoding aarch64_vector_crypto_sha2op_sha1_sched1 
					when ('00', '00010') => __encoding aarch64_vector_crypto_sha2op_sha256_sched0 
					when ('00', '00011') => __UNALLOCATED
					when ('1x', _) => __UNALLOCATED
			when ('0110', _, '0x', 'x101', '00xxxxx10', _) => __UNPREDICTABLE
			when ('0111', _, '0x', 'x0xx', 'xxx0xxxx0', _) => __UNPREDICTABLE
			when ('0111', _, '0x', 'x101', '00xxxxx10', _) => __UNPREDICTABLE
			when ('01x1', _, '00', '00xx', 'xxx0xxxx1', _) => 
				__field op 29 +: 1
				__field imm5 16 +: 5
				__field imm4 11 +: 4
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (op, imm5, imm4) of
					when ('0', _, 'xxx1') => __UNALLOCATED
					when ('0', _, 'xx1x') => __UNALLOCATED
					when ('0', _, 'x1xx') => __UNALLOCATED
					when ('0', _, '0000') => __encoding aarch64_vector_transfer_vector_cpy_dup_sisd 
					when ('0', _, '1xxx') => __UNALLOCATED
					when ('0', 'x0000', '0000') => __UNALLOCATED
					when ('1', _, _) => __UNALLOCATED
			when ('01x1', _, '01', '00xx', 'xxx0xxxx1', _) => __UNPREDICTABLE
			when ('01x1', _, '0x', '0111', '00xxxxx10', _) => __UNPREDICTABLE
			when ('01x1', _, '0x', '10xx', 'xxx00xxx1', _) => 
				__field U 29 +: 1
				__field a 23 +: 1
				__field Rm 16 +: 5
				__field opcode 11 +: 3
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (U, a, opcode) of
					when (_, _, '110') => __UNALLOCATED
					when (_, '1', '011') => __UNALLOCATED
					when ('0', '0', '011') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_fp16_extended_sisd 
					when ('0', '0', '100') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_fp16_sisd 
					when ('0', '0', '101') => __UNALLOCATED
					when ('0', '0', '111') => __encoding aarch64_vector_arithmetic_binary_uniform_recps_fp16_sisd 
					when ('0', '1', '100') => __UNALLOCATED
					when ('0', '1', '101') => __UNALLOCATED
					when ('0', '1', '111') => __encoding aarch64_vector_arithmetic_binary_uniform_rsqrts_fp16_sisd 
					when ('1', '0', '011') => __UNALLOCATED
					when ('1', '0', '100') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_fp16_sisd 
					when ('1', '0', '101') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_fp16_sisd 
					when ('1', '0', '111') => __UNALLOCATED
					when ('1', '1', '010') => __encoding aarch64_vector_arithmetic_binary_uniform_sub_fp16_sisd 
					when ('1', '1', '100') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_fp16_sisd 
					when ('1', '1', '101') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_fp16_sisd 
					when ('1', '1', '111') => __UNALLOCATED
			when ('01x1', _, '0x', '10xx', 'xxx01xxx1', _) => __UNPREDICTABLE
			when ('01x1', _, '0x', '1111', '00xxxxx10', _) => 
				__field U 29 +: 1
				__field a 23 +: 1
				__field opcode 12 +: 5
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (U, a, opcode) of
					when (_, _, '00xxx') => __UNALLOCATED
					when (_, _, '010xx') => __UNALLOCATED
					when (_, _, '10xxx') => __UNALLOCATED
					when (_, _, '1100x') => __UNALLOCATED
					when (_, _, '11110') => __UNALLOCATED
					when (_, '0', '011xx') => __UNALLOCATED
					when (_, '0', '11111') => __UNALLOCATED
					when (_, '1', '01111') => __UNALLOCATED
					when (_, '1', '11100') => __UNALLOCATED
					when ('0', '0', '11010') => __encoding aarch64_vector_arithmetic_unary_fp16_conv_float_bulk_sisd 
					when ('0', '0', '11011') => __encoding aarch64_vector_arithmetic_unary_fp16_conv_float_bulk_sisd 
					when ('0', '0', '11100') => __encoding aarch64_vector_arithmetic_unary_fp16_conv_float_tieaway_sisd 
					when ('0', '0', '11101') => __encoding aarch64_vector_arithmetic_unary_fp16_conv_int_sisd 
					when ('0', '1', '01100') => __encoding aarch64_vector_arithmetic_unary_cmp_fp16_bulk_sisd 
					when ('0', '1', '01101') => __encoding aarch64_vector_arithmetic_unary_cmp_fp16_bulk_sisd 
					when ('0', '1', '01110') => __encoding aarch64_vector_arithmetic_unary_cmp_fp16_lessthan_sisd 
					when ('0', '1', '11010') => __encoding aarch64_vector_arithmetic_unary_fp16_conv_float_bulk_sisd 
					when ('0', '1', '11011') => __encoding aarch64_vector_arithmetic_unary_fp16_conv_float_bulk_sisd 
					when ('0', '1', '11101') => __encoding aarch64_vector_arithmetic_unary_special_recip_fp16_sisd 
					when ('0', '1', '11111') => __encoding aarch64_vector_arithmetic_unary_special_frecpx_fp16 
					when ('1', '0', '11010') => __encoding aarch64_vector_arithmetic_unary_fp16_conv_float_bulk_sisd 
					when ('1', '0', '11011') => __encoding aarch64_vector_arithmetic_unary_fp16_conv_float_bulk_sisd 
					when ('1', '0', '11100') => __encoding aarch64_vector_arithmetic_unary_fp16_conv_float_tieaway_sisd 
					when ('1', '0', '11101') => __encoding aarch64_vector_arithmetic_unary_fp16_conv_int_sisd 
					when ('1', '1', '01100') => __encoding aarch64_vector_arithmetic_unary_cmp_fp16_bulk_sisd 
					when ('1', '1', '01101') => __encoding aarch64_vector_arithmetic_unary_cmp_fp16_bulk_sisd 
					when ('1', '1', '01110') => __UNALLOCATED
					when ('1', '1', '11010') => __encoding aarch64_vector_arithmetic_unary_fp16_conv_float_bulk_sisd 
					when ('1', '1', '11011') => __encoding aarch64_vector_arithmetic_unary_fp16_conv_float_bulk_sisd 
					when ('1', '1', '11101') => __encoding aarch64_vector_arithmetic_unary_special_sqrt_est_fp16_sisd 
					when ('1', '1', '11111') => __UNALLOCATED
			when ('01x1', _, '0x', 'x0xx', 'xxx1xxxx0', _) => __UNPREDICTABLE
			when ('01x1', _, '0x', 'x0xx', 'xxx1xxxx1', _) => 
				__field U 29 +: 1
				__field size 22 +: 2
				__field Rm 16 +: 5
				__field opcode 11 +: 4
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (U, opcode) of
					when (_, '001x') => __UNALLOCATED
					when (_, '01xx') => __UNALLOCATED
					when (_, '1xxx') => __UNALLOCATED
					when ('0', '0000') => __UNALLOCATED
					when ('0', '0001') => __UNALLOCATED
					when ('1', '0000') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_int_doubling_accum_sisd 
					when ('1', '0001') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_int_doubling_accum_sisd 
			when ('01x1', _, '0x', 'x100', '00xxxxx10', _) => 
				__field U 29 +: 1
				__field size 22 +: 2
				__field opcode 12 +: 5
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (U, size, opcode) of
					when (_, _, '0000x') => __UNALLOCATED
					when (_, _, '00010') => __UNALLOCATED
					when (_, _, '0010x') => __UNALLOCATED
					when (_, _, '00110') => __UNALLOCATED
					when (_, _, '01111') => __UNALLOCATED
					when (_, _, '1000x') => __UNALLOCATED
					when (_, _, '10011') => __UNALLOCATED
					when (_, _, '10101') => __UNALLOCATED
					when (_, _, '10111') => __UNALLOCATED
					when (_, _, '1100x') => __UNALLOCATED
					when (_, _, '11110') => __UNALLOCATED
					when (_, '0x', '011xx') => __UNALLOCATED
					when (_, '0x', '11111') => __UNALLOCATED
					when (_, '1x', '10110') => __UNALLOCATED
					when (_, '1x', '11100') => __UNALLOCATED
					when ('0', _, '00011') => __encoding aarch64_vector_arithmetic_unary_add_saturating_sisd 
					when ('0', _, '00111') => __encoding aarch64_vector_arithmetic_unary_diff_neg_sat_sisd 
					when ('0', _, '01000') => __encoding aarch64_vector_arithmetic_unary_cmp_int_bulk_sisd 
					when ('0', _, '01001') => __encoding aarch64_vector_arithmetic_unary_cmp_int_bulk_sisd 
					when ('0', _, '01010') => __encoding aarch64_vector_arithmetic_unary_cmp_int_lessthan_sisd 
					when ('0', _, '01011') => __encoding aarch64_vector_arithmetic_unary_diff_neg_int_sisd 
					when ('0', _, '10010') => __UNALLOCATED
					when ('0', _, '10100') => __encoding aarch64_vector_arithmetic_unary_extract_sat_sisd 
					when ('0', '0x', '10110') => __UNALLOCATED
					when ('0', '0x', '11010') => __encoding aarch64_vector_arithmetic_unary_float_conv_float_bulk_sisd 
					when ('0', '0x', '11011') => __encoding aarch64_vector_arithmetic_unary_float_conv_float_bulk_sisd 
					when ('0', '0x', '11100') => __encoding aarch64_vector_arithmetic_unary_float_conv_float_tieaway_sisd 
					when ('0', '0x', '11101') => __encoding aarch64_vector_arithmetic_unary_float_conv_int_sisd 
					when ('0', '1x', '01100') => __encoding aarch64_vector_arithmetic_unary_cmp_float_bulk_sisd 
					when ('0', '1x', '01101') => __encoding aarch64_vector_arithmetic_unary_cmp_float_bulk_sisd 
					when ('0', '1x', '01110') => __encoding aarch64_vector_arithmetic_unary_cmp_float_lessthan_sisd 
					when ('0', '1x', '11010') => __encoding aarch64_vector_arithmetic_unary_float_conv_float_bulk_sisd 
					when ('0', '1x', '11011') => __encoding aarch64_vector_arithmetic_unary_float_conv_float_bulk_sisd 
					when ('0', '1x', '11101') => __encoding aarch64_vector_arithmetic_unary_special_recip_float_sisd 
					when ('0', '1x', '11111') => __encoding aarch64_vector_arithmetic_unary_special_frecpx 
					when ('1', _, '00011') => __encoding aarch64_vector_arithmetic_unary_add_saturating_sisd 
					when ('1', _, '00111') => __encoding aarch64_vector_arithmetic_unary_diff_neg_sat_sisd 
					when ('1', _, '01000') => __encoding aarch64_vector_arithmetic_unary_cmp_int_bulk_sisd 
					when ('1', _, '01001') => __encoding aarch64_vector_arithmetic_unary_cmp_int_bulk_sisd 
					when ('1', _, '01010') => __UNALLOCATED
					when ('1', _, '01011') => __encoding aarch64_vector_arithmetic_unary_diff_neg_int_sisd 
					when ('1', _, '10010') => __encoding aarch64_vector_arithmetic_unary_extract_sqxtun_sisd 
					when ('1', _, '10100') => __encoding aarch64_vector_arithmetic_unary_extract_sat_sisd 
					when ('1', '0x', '10110') => __encoding aarch64_vector_arithmetic_unary_float_xtn_sisd 
					when ('1', '0x', '11010') => __encoding aarch64_vector_arithmetic_unary_float_conv_float_bulk_sisd 
					when ('1', '0x', '11011') => __encoding aarch64_vector_arithmetic_unary_float_conv_float_bulk_sisd 
					when ('1', '0x', '11100') => __encoding aarch64_vector_arithmetic_unary_float_conv_float_tieaway_sisd 
					when ('1', '0x', '11101') => __encoding aarch64_vector_arithmetic_unary_float_conv_int_sisd 
					when ('1', '1x', '01100') => __encoding aarch64_vector_arithmetic_unary_cmp_float_bulk_sisd 
					when ('1', '1x', '01101') => __encoding aarch64_vector_arithmetic_unary_cmp_float_bulk_sisd 
					when ('1', '1x', '01110') => __UNALLOCATED
					when ('1', '1x', '11010') => __encoding aarch64_vector_arithmetic_unary_float_conv_float_bulk_sisd 
					when ('1', '1x', '11011') => __encoding aarch64_vector_arithmetic_unary_float_conv_float_bulk_sisd 
					when ('1', '1x', '11101') => __encoding aarch64_vector_arithmetic_unary_special_sqrt_est_float_sisd 
					when ('1', '1x', '11111') => __UNALLOCATED
			when ('01x1', _, '0x', 'x110', '00xxxxx10', _) => 
				__field U 29 +: 1
				__field size 22 +: 2
				__field opcode 12 +: 5
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (U, size, opcode) of
					when (_, _, '00xxx') => __UNALLOCATED
					when (_, _, '010xx') => __UNALLOCATED
					when (_, _, '01110') => __UNALLOCATED
					when (_, _, '10xxx') => __UNALLOCATED
					when (_, _, '1100x') => __UNALLOCATED
					when (_, _, '11010') => __UNALLOCATED
					when (_, _, '111xx') => __UNALLOCATED
					when (_, '1x', '01101') => __UNALLOCATED
					when ('0', _, '11011') => __encoding aarch64_vector_reduce_add_sisd 
					when ('0', '00', '01100') => __encoding aarch64_vector_reduce_fp16_maxnm_sisd 
					when ('0', '00', '01101') => __encoding aarch64_vector_reduce_fp16_add_sisd 
					when ('0', '00', '01111') => __encoding aarch64_vector_reduce_fp16_max_sisd 
					when ('0', '01', '01100') => __UNALLOCATED
					when ('0', '01', '01101') => __UNALLOCATED
					when ('0', '01', '01111') => __UNALLOCATED
					when ('0', '10', '01100') => __encoding aarch64_vector_reduce_fp16_maxnm_sisd 
					when ('0', '10', '01111') => __encoding aarch64_vector_reduce_fp16_max_sisd 
					when ('0', '11', '01100') => __UNALLOCATED
					when ('0', '11', '01111') => __UNALLOCATED
					when ('1', _, '11011') => __UNALLOCATED
					when ('1', '0x', '01100') => __encoding aarch64_vector_reduce_fp_maxnm_sisd 
					when ('1', '0x', '01101') => __encoding aarch64_vector_reduce_fp_add_sisd 
					when ('1', '0x', '01111') => __encoding aarch64_vector_reduce_fp_max_sisd 
					when ('1', '1x', '01100') => __encoding aarch64_vector_reduce_fp_maxnm_sisd 
					when ('1', '1x', '01111') => __encoding aarch64_vector_reduce_fp_max_sisd 
			when ('01x1', _, '0x', 'x1xx', '1xxxxxx10', _) => __UNPREDICTABLE
			when ('01x1', _, '0x', 'x1xx', 'x1xxxxx10', _) => __UNPREDICTABLE
			when ('01x1', _, '0x', 'x1xx', 'xxxxxxx00', _) => 
				__field U 29 +: 1
				__field size 22 +: 2
				__field Rm 16 +: 5
				__field opcode 12 +: 4
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (U, opcode) of
					when (_, '00xx') => __UNALLOCATED
					when (_, '01xx') => __UNALLOCATED
					when (_, '1000') => __UNALLOCATED
					when (_, '1010') => __UNALLOCATED
					when (_, '1100') => __UNALLOCATED
					when (_, '111x') => __UNALLOCATED
					when ('0', '1001') => __encoding aarch64_vector_arithmetic_binary_disparate_mul_dmacc_sisd 
					when ('0', '1011') => __encoding aarch64_vector_arithmetic_binary_disparate_mul_dmacc_sisd 
					when ('0', '1101') => __encoding aarch64_vector_arithmetic_binary_disparate_mul_double_sisd 
					when ('1', '1001') => __UNALLOCATED
					when ('1', '1011') => __UNALLOCATED
					when ('1', '1101') => __UNALLOCATED
			when ('01x1', _, '0x', 'x1xx', 'xxxxxxxx1', _) => 
				__field U 29 +: 1
				__field size 22 +: 2
				__field Rm 16 +: 5
				__field opcode 11 +: 5
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (U, size, opcode) of
					when (_, _, '00000') => __UNALLOCATED
					when (_, _, '0001x') => __UNALLOCATED
					when (_, _, '00100') => __UNALLOCATED
					when (_, _, '011xx') => __UNALLOCATED
					when (_, _, '1001x') => __UNALLOCATED
					when (_, '1x', '11011') => __UNALLOCATED
					when ('0', _, '00001') => __encoding aarch64_vector_arithmetic_binary_uniform_add_saturating_sisd 
					when ('0', _, '00101') => __encoding aarch64_vector_arithmetic_binary_uniform_sub_saturating_sisd 
					when ('0', _, '00110') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_int_sisd 
					when ('0', _, '00111') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_int_sisd 
					when ('0', _, '01000') => __encoding aarch64_vector_arithmetic_binary_uniform_shift_sisd 
					when ('0', _, '01001') => __encoding aarch64_vector_arithmetic_binary_uniform_shift_sisd 
					when ('0', _, '01010') => __encoding aarch64_vector_arithmetic_binary_uniform_shift_sisd 
					when ('0', _, '01011') => __encoding aarch64_vector_arithmetic_binary_uniform_shift_sisd 
					when ('0', _, '10000') => __encoding aarch64_vector_arithmetic_binary_uniform_add_wrapping_single_sisd 
					when ('0', _, '10001') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_bitwise_sisd 
					when ('0', _, '10100') => __UNALLOCATED
					when ('0', _, '10101') => __UNALLOCATED
					when ('0', _, '10110') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_int_doubling_sisd 
					when ('0', _, '10111') => __UNALLOCATED
					when ('0', '0x', '11000') => __UNALLOCATED
					when ('0', '0x', '11001') => __UNALLOCATED
					when ('0', '0x', '11010') => __UNALLOCATED
					when ('0', '0x', '11011') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_fp_extended_sisd 
					when ('0', '0x', '11100') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_fp_sisd 
					when ('0', '0x', '11101') => __UNALLOCATED
					when ('0', '0x', '11110') => __UNALLOCATED
					when ('0', '0x', '11111') => __encoding aarch64_vector_arithmetic_binary_uniform_recps_sisd 
					when ('0', '1x', '11000') => __UNALLOCATED
					when ('0', '1x', '11001') => __UNALLOCATED
					when ('0', '1x', '11010') => __UNALLOCATED
					when ('0', '1x', '11100') => __UNALLOCATED
					when ('0', '1x', '11101') => __UNALLOCATED
					when ('0', '1x', '11110') => __UNALLOCATED
					when ('0', '1x', '11111') => __encoding aarch64_vector_arithmetic_binary_uniform_rsqrts_sisd 
					when ('1', _, '00001') => __encoding aarch64_vector_arithmetic_binary_uniform_add_saturating_sisd 
					when ('1', _, '00101') => __encoding aarch64_vector_arithmetic_binary_uniform_sub_saturating_sisd 
					when ('1', _, '00110') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_int_sisd 
					when ('1', _, '00111') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_int_sisd 
					when ('1', _, '01000') => __encoding aarch64_vector_arithmetic_binary_uniform_shift_sisd 
					when ('1', _, '01001') => __encoding aarch64_vector_arithmetic_binary_uniform_shift_sisd 
					when ('1', _, '01010') => __encoding aarch64_vector_arithmetic_binary_uniform_shift_sisd 
					when ('1', _, '01011') => __encoding aarch64_vector_arithmetic_binary_uniform_shift_sisd 
					when ('1', _, '10000') => __encoding aarch64_vector_arithmetic_binary_uniform_add_wrapping_single_sisd 
					when ('1', _, '10001') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_bitwise_sisd 
					when ('1', _, '10100') => __UNALLOCATED
					when ('1', _, '10101') => __UNALLOCATED
					when ('1', _, '10110') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_int_doubling_sisd 
					when ('1', _, '10111') => __UNALLOCATED
					when ('1', '0x', '11000') => __UNALLOCATED
					when ('1', '0x', '11001') => __UNALLOCATED
					when ('1', '0x', '11010') => __UNALLOCATED
					when ('1', '0x', '11011') => __UNALLOCATED
					when ('1', '0x', '11100') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_fp_sisd 
					when ('1', '0x', '11101') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_fp_sisd 
					when ('1', '0x', '11110') => __UNALLOCATED
					when ('1', '0x', '11111') => __UNALLOCATED
					when ('1', '1x', '11000') => __UNALLOCATED
					when ('1', '1x', '11001') => __UNALLOCATED
					when ('1', '1x', '11010') => __encoding aarch64_vector_arithmetic_binary_uniform_sub_fp_sisd 
					when ('1', '1x', '11100') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_fp_sisd 
					when ('1', '1x', '11101') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_fp_sisd 
					when ('1', '1x', '11110') => __UNALLOCATED
					when ('1', '1x', '11111') => __UNALLOCATED
			when ('01x1', _, '10', _, 'xxxxxxxx1', _) => 
				__field U 29 +: 1
				__field immh 19 +: 4
				__field immb 16 +: 3
				__field opcode 11 +: 5
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (U, immh, opcode) of
					when (_, !'0000', '00001') => __UNALLOCATED
					when (_, !'0000', '00011') => __UNALLOCATED
					when (_, !'0000', '00101') => __UNALLOCATED
					when (_, !'0000', '00111') => __UNALLOCATED
					when (_, !'0000', '01001') => __UNALLOCATED
					when (_, !'0000', '01011') => __UNALLOCATED
					when (_, !'0000', '01101') => __UNALLOCATED
					when (_, !'0000', '01111') => __UNALLOCATED
					when (_, !'0000', '101xx') => __UNALLOCATED
					when (_, !'0000', '110xx') => __UNALLOCATED
					when (_, !'0000', '11101') => __UNALLOCATED
					when (_, !'0000', '11110') => __UNALLOCATED
					when (_, '0000', _) => __UNALLOCATED
					when ('0', !'0000', '00000') => __encoding aarch64_vector_shift_right_sisd 
					when ('0', !'0000', '00010') => __encoding aarch64_vector_shift_right_sisd 
					when ('0', !'0000', '00100') => __encoding aarch64_vector_shift_right_sisd 
					when ('0', !'0000', '00110') => __encoding aarch64_vector_shift_right_sisd 
					when ('0', !'0000', '01000') => __UNALLOCATED
					when ('0', !'0000', '01010') => __encoding aarch64_vector_shift_left_sisd 
					when ('0', !'0000', '01100') => __UNALLOCATED
					when ('0', !'0000', '01110') => __encoding aarch64_vector_shift_left_sat_sisd 
					when ('0', !'0000', '10000') => __UNALLOCATED
					when ('0', !'0000', '10001') => __UNALLOCATED
					when ('0', !'0000', '10010') => __encoding aarch64_vector_shift_right_narrow_uniform_sisd 
					when ('0', !'0000', '10011') => __encoding aarch64_vector_shift_right_narrow_uniform_sisd 
					when ('0', !'0000', '11100') => __encoding aarch64_vector_shift_conv_int_sisd 
					when ('0', !'0000', '11111') => __encoding aarch64_vector_shift_conv_float_sisd 
					when ('1', !'0000', '00000') => __encoding aarch64_vector_shift_right_sisd 
					when ('1', !'0000', '00010') => __encoding aarch64_vector_shift_right_sisd 
					when ('1', !'0000', '00100') => __encoding aarch64_vector_shift_right_sisd 
					when ('1', !'0000', '00110') => __encoding aarch64_vector_shift_right_sisd 
					when ('1', !'0000', '01000') => __encoding aarch64_vector_shift_right_insert_sisd 
					when ('1', !'0000', '01010') => __encoding aarch64_vector_shift_left_insert_sisd 
					when ('1', !'0000', '01100') => __encoding aarch64_vector_shift_left_sat_sisd 
					when ('1', !'0000', '01110') => __encoding aarch64_vector_shift_left_sat_sisd 
					when ('1', !'0000', '10000') => __encoding aarch64_vector_shift_right_narrow_nonuniform_sisd 
					when ('1', !'0000', '10001') => __encoding aarch64_vector_shift_right_narrow_nonuniform_sisd 
					when ('1', !'0000', '10010') => __encoding aarch64_vector_shift_right_narrow_uniform_sisd 
					when ('1', !'0000', '10011') => __encoding aarch64_vector_shift_right_narrow_uniform_sisd 
					when ('1', !'0000', '11100') => __encoding aarch64_vector_shift_conv_int_sisd 
					when ('1', !'0000', '11111') => __encoding aarch64_vector_shift_conv_float_sisd 
			when ('01x1', _, '11', _, 'xxxxxxxx1', _) => __UNPREDICTABLE
			when ('01x1', _, '1x', _, 'xxxxxxxx0', _) => 
				__field U 29 +: 1
				__field size 22 +: 2
				__field L 21 +: 1
				__field M 20 +: 1
				__field Rm 16 +: 4
				__field opcode 12 +: 4
				__field H 11 +: 1
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (U, size, opcode) of
					when (_, _, '0000') => __UNALLOCATED
					when (_, _, '0010') => __UNALLOCATED
					when (_, _, '0100') => __UNALLOCATED
					when (_, _, '0110') => __UNALLOCATED
					when (_, _, '1000') => __UNALLOCATED
					when (_, _, '1010') => __UNALLOCATED
					when (_, _, '1110') => __UNALLOCATED
					when (_, '01', '0001') => __UNALLOCATED
					when (_, '01', '0101') => __UNALLOCATED
					when (_, '01', '1001') => __UNALLOCATED
					when ('0', _, '0011') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_double_sisd 
					when ('0', _, '0111') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_double_sisd 
					when ('0', _, '1011') => __encoding aarch64_vector_arithmetic_binary_element_mul_double_sisd 
					when ('0', _, '1100') => __encoding aarch64_vector_arithmetic_binary_element_mul_high_sisd 
					when ('0', _, '1101') => __encoding aarch64_vector_arithmetic_binary_element_mul_high_sisd 
					when ('0', _, '1111') => __UNALLOCATED
					when ('0', '00', '0001') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_fp16_sisd 
					when ('0', '00', '0101') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_fp16_sisd 
					when ('0', '00', '1001') => __encoding aarch64_vector_arithmetic_binary_element_mul_fp16_sisd 
					when ('0', '1x', '0001') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_fp_sisd 
					when ('0', '1x', '0101') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_fp_sisd 
					when ('0', '1x', '1001') => __encoding aarch64_vector_arithmetic_binary_element_mul_fp_sisd 
					when ('1', _, '0011') => __UNALLOCATED
					when ('1', _, '0111') => __UNALLOCATED
					when ('1', _, '1011') => __UNALLOCATED
					when ('1', _, '1100') => __UNALLOCATED
					when ('1', _, '1101') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_high_sisd 
					when ('1', _, '1111') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_high_sisd 
					when ('1', '00', '0001') => __UNALLOCATED
					when ('1', '00', '0101') => __UNALLOCATED
					when ('1', '00', '1001') => __encoding aarch64_vector_arithmetic_binary_element_mul_fp16_sisd 
					when ('1', '1x', '0001') => __UNALLOCATED
					when ('1', '1x', '0101') => __UNALLOCATED
					when ('1', '1x', '1001') => __encoding aarch64_vector_arithmetic_binary_element_mul_fp_sisd 
			when ('0x00', _, '0x', 'x0xx', 'xxx0xxx00', _) => 
				__field Q 30 +: 1
				__field op2 22 +: 2
				__field Rm 16 +: 5
				__field len 13 +: 2
				__field op 12 +: 1
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (op2, len, op) of
					when ('x1', _, _) => __UNALLOCATED
					when ('00', '00', '0') => __encoding aarch64_vector_transfer_vector_table 
					when ('00', '00', '1') => __encoding aarch64_vector_transfer_vector_table 
					when ('00', '01', '0') => __encoding aarch64_vector_transfer_vector_table 
					when ('00', '01', '1') => __encoding aarch64_vector_transfer_vector_table 
					when ('00', '10', '0') => __encoding aarch64_vector_transfer_vector_table 
					when ('00', '10', '1') => __encoding aarch64_vector_transfer_vector_table 
					when ('00', '11', '0') => __encoding aarch64_vector_transfer_vector_table 
					when ('00', '11', '1') => __encoding aarch64_vector_transfer_vector_table 
					when ('1x', _, _) => __UNALLOCATED
			when ('0x00', _, '0x', 'x0xx', 'xxx0xxx10', _) => 
				__field Q 30 +: 1
				__field size 22 +: 2
				__field Rm 16 +: 5
				__field opcode 12 +: 3
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (opcode) of
					when ('000') => __UNALLOCATED
					when ('001') => __encoding aarch64_vector_transfer_vector_permute_unzip 
					when ('010') => __encoding aarch64_vector_transfer_vector_permute_transpose 
					when ('011') => __encoding aarch64_vector_transfer_vector_permute_zip 
					when ('100') => __UNALLOCATED
					when ('101') => __encoding aarch64_vector_transfer_vector_permute_unzip 
					when ('110') => __encoding aarch64_vector_transfer_vector_permute_transpose 
					when ('111') => __encoding aarch64_vector_transfer_vector_permute_zip 
			when ('0x10', _, '0x', 'x0xx', 'xxx0xxxx0', _) => 
				__field Q 30 +: 1
				__field op2 22 +: 2
				__field Rm 16 +: 5
				__field imm4 11 +: 4
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (op2) of
					when ('x1') => __UNALLOCATED
					when ('00') => __encoding aarch64_vector_transfer_vector_extract 
					when ('1x') => __UNALLOCATED
			when ('0xx0', _, '00', '00xx', 'xxx0xxxx1', _) => 
				__field Q 30 +: 1
				__field op 29 +: 1
				__field imm5 16 +: 5
				__field imm4 11 +: 4
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (Q, op, imm5, imm4) of
					when (_, _, 'x0000', _) => __UNALLOCATED
					when (_, '0', _, '0000') => __encoding aarch64_vector_transfer_vector_cpy_dup_simd 
					when (_, '0', _, '0001') => __encoding aarch64_vector_transfer_integer_dup 
					when (_, '0', _, '0010') => __UNALLOCATED
					when (_, '0', _, '0100') => __UNALLOCATED
					when (_, '0', _, '0110') => __UNALLOCATED
					when (_, '0', _, '1xxx') => __UNALLOCATED
					when ('0', '0', _, '0011') => __UNALLOCATED
					when ('0', '0', _, '0101') => __encoding aarch64_vector_transfer_integer_move_signed 
					when ('0', '0', _, '0111') => __encoding aarch64_vector_transfer_integer_move_unsigned 
					when ('0', '1', _, _) => __UNALLOCATED
					when ('1', '0', _, '0011') => __encoding aarch64_vector_transfer_integer_insert 
					when ('1', '0', _, '0101') => __encoding aarch64_vector_transfer_integer_move_signed 
					when ('1', '0', 'x1000', '0111') => __encoding aarch64_vector_transfer_integer_move_unsigned 
					when ('1', '1', _, _) => __encoding aarch64_vector_transfer_vector_insert 
			when ('0xx0', _, '01', '00xx', 'xxx0xxxx1', _) => __UNPREDICTABLE
			when ('0xx0', _, '0x', '0111', '00xxxxx10', _) => __UNPREDICTABLE
			when ('0xx0', _, '0x', '10xx', 'xxx00xxx1', _) => 
				__field Q 30 +: 1
				__field U 29 +: 1
				__field a 23 +: 1
				__field Rm 16 +: 5
				__field opcode 11 +: 3
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (U, a, opcode) of
					when ('0', '0', '000') => __encoding aarch64_vector_arithmetic_binary_uniform_max_min_fp16_2008 
					when ('0', '0', '001') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_fp16_fused 
					when ('0', '0', '010') => __encoding aarch64_vector_arithmetic_binary_uniform_add_fp16 
					when ('0', '0', '011') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_fp16_extended_simd 
					when ('0', '0', '100') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_fp16_simd 
					when ('0', '0', '101') => __UNALLOCATED
					when ('0', '0', '110') => __encoding aarch64_vector_arithmetic_binary_uniform_max_min_fp16_1985 
					when ('0', '0', '111') => __encoding aarch64_vector_arithmetic_binary_uniform_recps_fp16_simd 
					when ('0', '1', '000') => __encoding aarch64_vector_arithmetic_binary_uniform_max_min_fp16_2008 
					when ('0', '1', '001') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_fp16_fused 
					when ('0', '1', '010') => __encoding aarch64_vector_arithmetic_binary_uniform_sub_fp16_simd 
					when ('0', '1', '011') => __UNALLOCATED
					when ('0', '1', '100') => __UNALLOCATED
					when ('0', '1', '101') => __UNALLOCATED
					when ('0', '1', '110') => __encoding aarch64_vector_arithmetic_binary_uniform_max_min_fp16_1985 
					when ('0', '1', '111') => __encoding aarch64_vector_arithmetic_binary_uniform_rsqrts_fp16_simd 
					when ('1', '0', '000') => __encoding aarch64_vector_arithmetic_binary_uniform_max_min_fp16_2008 
					when ('1', '0', '001') => __UNALLOCATED
					when ('1', '0', '010') => __encoding aarch64_vector_arithmetic_binary_uniform_add_fp16 
					when ('1', '0', '011') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_fp16_product 
					when ('1', '0', '100') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_fp16_simd 
					when ('1', '0', '101') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_fp16_simd 
					when ('1', '0', '110') => __encoding aarch64_vector_arithmetic_binary_uniform_max_min_fp16_1985 
					when ('1', '0', '111') => __encoding aarch64_vector_arithmetic_binary_uniform_div_fp16 
					when ('1', '1', '000') => __encoding aarch64_vector_arithmetic_binary_uniform_max_min_fp16_2008 
					when ('1', '1', '001') => __UNALLOCATED
					when ('1', '1', '010') => __encoding aarch64_vector_arithmetic_binary_uniform_sub_fp16_simd 
					when ('1', '1', '011') => __UNALLOCATED
					when ('1', '1', '100') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_fp16_simd 
					when ('1', '1', '101') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_fp16_simd 
					when ('1', '1', '110') => __encoding aarch64_vector_arithmetic_binary_uniform_max_min_fp16_1985 
					when ('1', '1', '111') => __UNALLOCATED
			when ('0xx0', _, '0x', '10xx', 'xxx01xxx1', _) => __UNPREDICTABLE
			when ('0xx0', _, '0x', '1111', '00xxxxx10', _) => 
				__field Q 30 +: 1
				__field U 29 +: 1
				__field a 23 +: 1
				__field opcode 12 +: 5
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (U, a, opcode) of
					when (_, _, '00xxx') => __UNALLOCATED
					when (_, _, '010xx') => __UNALLOCATED
					when (_, _, '10xxx') => __UNALLOCATED
					when (_, _, '11110') => __UNALLOCATED
					when (_, '0', '011xx') => __UNALLOCATED
					when (_, '0', '11111') => __UNALLOCATED
					when (_, '1', '11100') => __UNALLOCATED
					when ('0', '0', '11000') => __encoding aarch64_vector_arithmetic_unary_fp16_round 
					when ('0', '0', '11001') => __encoding aarch64_vector_arithmetic_unary_fp16_round 
					when ('0', '0', '11010') => __encoding aarch64_vector_arithmetic_unary_fp16_conv_float_bulk_simd 
					when ('0', '0', '11011') => __encoding aarch64_vector_arithmetic_unary_fp16_conv_float_bulk_simd 
					when ('0', '0', '11100') => __encoding aarch64_vector_arithmetic_unary_fp16_conv_float_tieaway_simd 
					when ('0', '0', '11101') => __encoding aarch64_vector_arithmetic_unary_fp16_conv_int_simd 
					when ('0', '1', '01100') => __encoding aarch64_vector_arithmetic_unary_cmp_fp16_bulk_simd 
					when ('0', '1', '01101') => __encoding aarch64_vector_arithmetic_unary_cmp_fp16_bulk_simd 
					when ('0', '1', '01110') => __encoding aarch64_vector_arithmetic_unary_cmp_fp16_lessthan_simd 
					when ('0', '1', '01111') => __encoding aarch64_vector_arithmetic_unary_diff_neg_fp16 
					when ('0', '1', '11000') => __encoding aarch64_vector_arithmetic_unary_fp16_round 
					when ('0', '1', '11001') => __encoding aarch64_vector_arithmetic_unary_fp16_round 
					when ('0', '1', '11010') => __encoding aarch64_vector_arithmetic_unary_fp16_conv_float_bulk_simd 
					when ('0', '1', '11011') => __encoding aarch64_vector_arithmetic_unary_fp16_conv_float_bulk_simd 
					when ('0', '1', '11101') => __encoding aarch64_vector_arithmetic_unary_special_recip_fp16_simd 
					when ('0', '1', '11111') => __UNALLOCATED
					when ('1', '0', '11000') => __encoding aarch64_vector_arithmetic_unary_fp16_round 
					when ('1', '0', '11001') => __encoding aarch64_vector_arithmetic_unary_fp16_round 
					when ('1', '0', '11010') => __encoding aarch64_vector_arithmetic_unary_fp16_conv_float_bulk_simd 
					when ('1', '0', '11011') => __encoding aarch64_vector_arithmetic_unary_fp16_conv_float_bulk_simd 
					when ('1', '0', '11100') => __encoding aarch64_vector_arithmetic_unary_fp16_conv_float_tieaway_simd 
					when ('1', '0', '11101') => __encoding aarch64_vector_arithmetic_unary_fp16_conv_int_simd 
					when ('1', '1', '01100') => __encoding aarch64_vector_arithmetic_unary_cmp_fp16_bulk_simd 
					when ('1', '1', '01101') => __encoding aarch64_vector_arithmetic_unary_cmp_fp16_bulk_simd 
					when ('1', '1', '01110') => __UNALLOCATED
					when ('1', '1', '01111') => __encoding aarch64_vector_arithmetic_unary_diff_neg_fp16 
					when ('1', '1', '11000') => __UNALLOCATED
					when ('1', '1', '11001') => __encoding aarch64_vector_arithmetic_unary_fp16_round 
					when ('1', '1', '11010') => __encoding aarch64_vector_arithmetic_unary_fp16_conv_float_bulk_simd 
					when ('1', '1', '11011') => __encoding aarch64_vector_arithmetic_unary_fp16_conv_float_bulk_simd 
					when ('1', '1', '11101') => __encoding aarch64_vector_arithmetic_unary_special_sqrt_est_fp16_simd 
					when ('1', '1', '11111') => __encoding aarch64_vector_arithmetic_unary_special_sqrt_fp16 
			when ('0xx0', _, '0x', 'x0xx', 'xxx1xxxx0', _) => __UNPREDICTABLE
			when ('0xx0', _, '0x', 'x0xx', 'xxx1xxxx1', _) => 
				__field Q 30 +: 1
				__field U 29 +: 1
				__field size 22 +: 2
				__field Rm 16 +: 5
				__field opcode 11 +: 4
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (Q, U, size, opcode) of
					when (_, _, '0x', '0011') => __UNALLOCATED
					when (_, _, '11', '0011') => __UNALLOCATED
					when (_, '0', _, '0000') => __UNALLOCATED
					when (_, '0', _, '0001') => __UNALLOCATED
					when (_, '0', _, '0010') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_int_dotp 
					when (_, '0', _, '1xxx') => __UNALLOCATED
					when (_, '0', '10', '0011') => __encoding aarch64_vector_arithmetic_binary_uniform_mat_mul_int_usdot 
					when (_, '1', _, '0000') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_int_doubling_accum_simd 
					when (_, '1', _, '0001') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_int_doubling_accum_simd 
					when (_, '1', _, '0010') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_int_dotp 
					when (_, '1', _, '10xx') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_fp_complex 
					when (_, '1', _, '11x0') => __encoding aarch64_vector_arithmetic_binary_uniform_add_fp_complex 
					when (_, '1', '00', '1101') => __UNALLOCATED
					when (_, '1', '00', '1111') => __UNALLOCATED
					when (_, '1', '01', '1111') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_int_bfdot 
					when (_, '1', '1x', '1101') => __UNALLOCATED
					when (_, '1', '10', '0011') => __UNALLOCATED
					when (_, '1', '10', '1111') => __UNALLOCATED
					when (_, '1', '11', '1111') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_acc_bf16_long 
					when ('0', _, _, '01xx') => __UNALLOCATED
					when ('0', '1', '01', '1101') => __UNALLOCATED
					when ('1', _, '0x', '01xx') => __UNALLOCATED
					when ('1', _, '1x', '011x') => __UNALLOCATED
					when ('1', '0', '10', '0100') => __encoding aarch64_vector_arithmetic_binary_uniform_mat_mul_int_mla 
					when ('1', '0', '10', '0101') => __encoding aarch64_vector_arithmetic_binary_uniform_mat_mul_int_mla 
					when ('1', '1', '01', '1101') => __encoding aarch64_vector_bfmmla 
					when ('1', '1', '10', '0100') => __encoding aarch64_vector_arithmetic_binary_uniform_mat_mul_int_mla 
					when ('1', '1', '10', '0101') => __UNALLOCATED
			when ('0xx0', _, '0x', 'x100', '00xxxxx10', _) => 
				__field Q 30 +: 1
				__field U 29 +: 1
				__field size 22 +: 2
				__field opcode 12 +: 5
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (U, size, opcode) of
					when (_, _, '1000x') => __UNALLOCATED
					when (_, _, '10101') => __UNALLOCATED
					when (_, '0x', '011xx') => __UNALLOCATED
					when (_, '1x', '10111') => __UNALLOCATED
					when (_, '1x', '11110') => __UNALLOCATED
					when (_, '11', '10110') => __UNALLOCATED
					when ('0', _, '00000') => __encoding aarch64_vector_arithmetic_unary_rev 
					when ('0', _, '00001') => __encoding aarch64_vector_arithmetic_unary_rev 
					when ('0', _, '00010') => __encoding aarch64_vector_arithmetic_unary_add_pairwise 
					when ('0', _, '00011') => __encoding aarch64_vector_arithmetic_unary_add_saturating_simd 
					when ('0', _, '00100') => __encoding aarch64_vector_arithmetic_unary_clsz 
					when ('0', _, '00101') => __encoding aarch64_vector_arithmetic_unary_cnt 
					when ('0', _, '00110') => __encoding aarch64_vector_arithmetic_unary_add_pairwise 
					when ('0', _, '00111') => __encoding aarch64_vector_arithmetic_unary_diff_neg_sat_simd 
					when ('0', _, '01000') => __encoding aarch64_vector_arithmetic_unary_cmp_int_bulk_simd 
					when ('0', _, '01001') => __encoding aarch64_vector_arithmetic_unary_cmp_int_bulk_simd 
					when ('0', _, '01010') => __encoding aarch64_vector_arithmetic_unary_cmp_int_lessthan_simd 
					when ('0', _, '01011') => __encoding aarch64_vector_arithmetic_unary_diff_neg_int_simd 
					when ('0', _, '10010') => __encoding aarch64_vector_arithmetic_unary_extract_nosat 
					when ('0', _, '10011') => __UNALLOCATED
					when ('0', _, '10100') => __encoding aarch64_vector_arithmetic_unary_extract_sat_simd 
					when ('0', '0x', '10110') => __encoding aarch64_vector_arithmetic_unary_float_narrow 
					when ('0', '0x', '10111') => __encoding aarch64_vector_arithmetic_unary_float_widen 
					when ('0', '0x', '11000') => __encoding aarch64_vector_arithmetic_unary_float_round 
					when ('0', '0x', '11001') => __encoding aarch64_vector_arithmetic_unary_float_round 
					when ('0', '0x', '11010') => __encoding aarch64_vector_arithmetic_unary_float_conv_float_bulk_simd 
					when ('0', '0x', '11011') => __encoding aarch64_vector_arithmetic_unary_float_conv_float_bulk_simd 
					when ('0', '0x', '11100') => __encoding aarch64_vector_arithmetic_unary_float_conv_float_tieaway_simd 
					when ('0', '0x', '11101') => __encoding aarch64_vector_arithmetic_unary_float_conv_int_simd 
					when ('0', '0x', '11110') => __encoding aarch64_vector_arithmetic_unary_float_round_frint_32_64 
					when ('0', '0x', '11111') => __encoding aarch64_vector_arithmetic_unary_float_round_frint_32_64 
					when ('0', '1x', '01100') => __encoding aarch64_vector_arithmetic_unary_cmp_float_bulk_simd 
					when ('0', '1x', '01101') => __encoding aarch64_vector_arithmetic_unary_cmp_float_bulk_simd 
					when ('0', '1x', '01110') => __encoding aarch64_vector_arithmetic_unary_cmp_float_lessthan_simd 
					when ('0', '1x', '01111') => __encoding aarch64_vector_arithmetic_unary_diff_neg_float 
					when ('0', '1x', '11000') => __encoding aarch64_vector_arithmetic_unary_float_round 
					when ('0', '1x', '11001') => __encoding aarch64_vector_arithmetic_unary_float_round 
					when ('0', '1x', '11010') => __encoding aarch64_vector_arithmetic_unary_float_conv_float_bulk_simd 
					when ('0', '1x', '11011') => __encoding aarch64_vector_arithmetic_unary_float_conv_float_bulk_simd 
					when ('0', '1x', '11100') => __encoding aarch64_vector_arithmetic_unary_special_recip_int 
					when ('0', '1x', '11101') => __encoding aarch64_vector_arithmetic_unary_special_recip_float_simd 
					when ('0', '1x', '11111') => __UNALLOCATED
					when ('0', '10', '10110') => __encoding aarch64_vector_cvt_bf16_vector 
					when ('1', _, '00000') => __encoding aarch64_vector_arithmetic_unary_rev 
					when ('1', _, '00001') => __UNALLOCATED
					when ('1', _, '00010') => __encoding aarch64_vector_arithmetic_unary_add_pairwise 
					when ('1', _, '00011') => __encoding aarch64_vector_arithmetic_unary_add_saturating_simd 
					when ('1', _, '00100') => __encoding aarch64_vector_arithmetic_unary_clsz 
					when ('1', _, '00110') => __encoding aarch64_vector_arithmetic_unary_add_pairwise 
					when ('1', _, '00111') => __encoding aarch64_vector_arithmetic_unary_diff_neg_sat_simd 
					when ('1', _, '01000') => __encoding aarch64_vector_arithmetic_unary_cmp_int_bulk_simd 
					when ('1', _, '01001') => __encoding aarch64_vector_arithmetic_unary_cmp_int_bulk_simd 
					when ('1', _, '01010') => __UNALLOCATED
					when ('1', _, '01011') => __encoding aarch64_vector_arithmetic_unary_diff_neg_int_simd 
					when ('1', _, '10010') => __encoding aarch64_vector_arithmetic_unary_extract_sqxtun_simd 
					when ('1', _, '10011') => __encoding aarch64_vector_arithmetic_unary_shift 
					when ('1', _, '10100') => __encoding aarch64_vector_arithmetic_unary_extract_sat_simd 
					when ('1', '0x', '10110') => __encoding aarch64_vector_arithmetic_unary_float_xtn_simd 
					when ('1', '0x', '10111') => __UNALLOCATED
					when ('1', '0x', '11000') => __encoding aarch64_vector_arithmetic_unary_float_round 
					when ('1', '0x', '11001') => __encoding aarch64_vector_arithmetic_unary_float_round 
					when ('1', '0x', '11010') => __encoding aarch64_vector_arithmetic_unary_float_conv_float_bulk_simd 
					when ('1', '0x', '11011') => __encoding aarch64_vector_arithmetic_unary_float_conv_float_bulk_simd 
					when ('1', '0x', '11100') => __encoding aarch64_vector_arithmetic_unary_float_conv_float_tieaway_simd 
					when ('1', '0x', '11101') => __encoding aarch64_vector_arithmetic_unary_float_conv_int_simd 
					when ('1', '0x', '11110') => __encoding aarch64_vector_arithmetic_unary_float_round_frint_32_64 
					when ('1', '0x', '11111') => __encoding aarch64_vector_arithmetic_unary_float_round_frint_32_64 
					when ('1', '00', '00101') => __encoding aarch64_vector_arithmetic_unary_not 
					when ('1', '01', '00101') => __encoding aarch64_vector_arithmetic_unary_rbit 
					when ('1', '1x', '00101') => __UNALLOCATED
					when ('1', '1x', '01100') => __encoding aarch64_vector_arithmetic_unary_cmp_float_bulk_simd 
					when ('1', '1x', '01101') => __encoding aarch64_vector_arithmetic_unary_cmp_float_bulk_simd 
					when ('1', '1x', '01110') => __UNALLOCATED
					when ('1', '1x', '01111') => __encoding aarch64_vector_arithmetic_unary_diff_neg_float 
					when ('1', '1x', '11000') => __UNALLOCATED
					when ('1', '1x', '11001') => __encoding aarch64_vector_arithmetic_unary_float_round 
					when ('1', '1x', '11010') => __encoding aarch64_vector_arithmetic_unary_float_conv_float_bulk_simd 
					when ('1', '1x', '11011') => __encoding aarch64_vector_arithmetic_unary_float_conv_float_bulk_simd 
					when ('1', '1x', '11100') => __encoding aarch64_vector_arithmetic_unary_special_sqrt_est_int 
					when ('1', '1x', '11101') => __encoding aarch64_vector_arithmetic_unary_special_sqrt_est_float_simd 
					when ('1', '1x', '11111') => __encoding aarch64_vector_arithmetic_unary_special_sqrt 
					when ('1', '10', '10110') => __UNALLOCATED
			when ('0xx0', _, '0x', 'x110', '00xxxxx10', _) => 
				__field Q 30 +: 1
				__field U 29 +: 1
				__field size 22 +: 2
				__field opcode 12 +: 5
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (U, size, opcode) of
					when (_, _, '0000x') => __UNALLOCATED
					when (_, _, '00010') => __UNALLOCATED
					when (_, _, '001xx') => __UNALLOCATED
					when (_, _, '0100x') => __UNALLOCATED
					when (_, _, '01011') => __UNALLOCATED
					when (_, _, '01101') => __UNALLOCATED
					when (_, _, '01110') => __UNALLOCATED
					when (_, _, '10xxx') => __UNALLOCATED
					when (_, _, '1100x') => __UNALLOCATED
					when (_, _, '111xx') => __UNALLOCATED
					when ('0', _, '00011') => __encoding aarch64_vector_reduce_add_long 
					when ('0', _, '01010') => __encoding aarch64_vector_reduce_int_max 
					when ('0', _, '11010') => __encoding aarch64_vector_reduce_int_max 
					when ('0', _, '11011') => __encoding aarch64_vector_reduce_add_simd 
					when ('0', '00', '01100') => __encoding aarch64_vector_reduce_fp16_maxnm_simd 
					when ('0', '00', '01111') => __encoding aarch64_vector_reduce_fp16_max_simd 
					when ('0', '01', '01100') => __UNALLOCATED
					when ('0', '01', '01111') => __UNALLOCATED
					when ('0', '10', '01100') => __encoding aarch64_vector_reduce_fp16_maxnm_simd 
					when ('0', '10', '01111') => __encoding aarch64_vector_reduce_fp16_max_simd 
					when ('0', '11', '01100') => __UNALLOCATED
					when ('0', '11', '01111') => __UNALLOCATED
					when ('1', _, '00011') => __encoding aarch64_vector_reduce_add_long 
					when ('1', _, '01010') => __encoding aarch64_vector_reduce_int_max 
					when ('1', _, '11010') => __encoding aarch64_vector_reduce_int_max 
					when ('1', _, '11011') => __UNALLOCATED
					when ('1', '0x', '01100') => __encoding aarch64_vector_reduce_fp_maxnm_simd 
					when ('1', '0x', '01111') => __encoding aarch64_vector_reduce_fp_max_simd 
					when ('1', '1x', '01100') => __encoding aarch64_vector_reduce_fp_maxnm_simd 
					when ('1', '1x', '01111') => __encoding aarch64_vector_reduce_fp_max_simd 
			when ('0xx0', _, '0x', 'x1xx', '1xxxxxx10', _) => __UNPREDICTABLE
			when ('0xx0', _, '0x', 'x1xx', 'x1xxxxx10', _) => __UNPREDICTABLE
			when ('0xx0', _, '0x', 'x1xx', 'xxxxxxx00', _) => 
				__field Q 30 +: 1
				__field U 29 +: 1
				__field size 22 +: 2
				__field Rm 16 +: 5
				__field opcode 12 +: 4
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (U, opcode) of
					when (_, '1111') => __UNALLOCATED
					when ('0', '0000') => __encoding aarch64_vector_arithmetic_binary_disparate_add_sub_long 
					when ('0', '0001') => __encoding aarch64_vector_arithmetic_binary_disparate_add_sub_wide 
					when ('0', '0010') => __encoding aarch64_vector_arithmetic_binary_disparate_add_sub_long 
					when ('0', '0011') => __encoding aarch64_vector_arithmetic_binary_disparate_add_sub_wide 
					when ('0', '0100') => __encoding aarch64_vector_arithmetic_binary_disparate_add_sub_narrow 
					when ('0', '0101') => __encoding aarch64_vector_arithmetic_binary_disparate_diff 
					when ('0', '0110') => __encoding aarch64_vector_arithmetic_binary_disparate_add_sub_narrow 
					when ('0', '0111') => __encoding aarch64_vector_arithmetic_binary_disparate_diff 
					when ('0', '1000') => __encoding aarch64_vector_arithmetic_binary_disparate_mul_accum 
					when ('0', '1001') => __encoding aarch64_vector_arithmetic_binary_disparate_mul_dmacc_simd 
					when ('0', '1010') => __encoding aarch64_vector_arithmetic_binary_disparate_mul_accum 
					when ('0', '1011') => __encoding aarch64_vector_arithmetic_binary_disparate_mul_dmacc_simd 
					when ('0', '1100') => __encoding aarch64_vector_arithmetic_binary_disparate_mul_product 
					when ('0', '1101') => __encoding aarch64_vector_arithmetic_binary_disparate_mul_double_simd 
					when ('0', '1110') => __encoding aarch64_vector_arithmetic_binary_disparate_mul_poly 
					when ('1', '0000') => __encoding aarch64_vector_arithmetic_binary_disparate_add_sub_long 
					when ('1', '0001') => __encoding aarch64_vector_arithmetic_binary_disparate_add_sub_wide 
					when ('1', '0010') => __encoding aarch64_vector_arithmetic_binary_disparate_add_sub_long 
					when ('1', '0011') => __encoding aarch64_vector_arithmetic_binary_disparate_add_sub_wide 
					when ('1', '0100') => __encoding aarch64_vector_arithmetic_binary_disparate_add_sub_narrow 
					when ('1', '0101') => __encoding aarch64_vector_arithmetic_binary_disparate_diff 
					when ('1', '0110') => __encoding aarch64_vector_arithmetic_binary_disparate_add_sub_narrow 
					when ('1', '0111') => __encoding aarch64_vector_arithmetic_binary_disparate_diff 
					when ('1', '1000') => __encoding aarch64_vector_arithmetic_binary_disparate_mul_accum 
					when ('1', '1001') => __UNALLOCATED
					when ('1', '1010') => __encoding aarch64_vector_arithmetic_binary_disparate_mul_accum 
					when ('1', '1011') => __UNALLOCATED
					when ('1', '1100') => __encoding aarch64_vector_arithmetic_binary_disparate_mul_product 
					when ('1', '1101') => __UNALLOCATED
					when ('1', '1110') => __UNALLOCATED
			when ('0xx0', _, '0x', 'x1xx', 'xxxxxxxx1', _) => 
				__field Q 30 +: 1
				__field U 29 +: 1
				__field size 22 +: 2
				__field Rm 16 +: 5
				__field opcode 11 +: 5
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (U, size, opcode) of
					when ('0', _, '00000') => __encoding aarch64_vector_arithmetic_binary_uniform_add_halving_truncating 
					when ('0', _, '00001') => __encoding aarch64_vector_arithmetic_binary_uniform_add_saturating_simd 
					when ('0', _, '00010') => __encoding aarch64_vector_arithmetic_binary_uniform_add_halving_rounding 
					when ('0', _, '00100') => __encoding aarch64_vector_arithmetic_binary_uniform_sub_int 
					when ('0', _, '00101') => __encoding aarch64_vector_arithmetic_binary_uniform_sub_saturating_simd 
					when ('0', _, '00110') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_int_simd 
					when ('0', _, '00111') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_int_simd 
					when ('0', _, '01000') => __encoding aarch64_vector_arithmetic_binary_uniform_shift_simd 
					when ('0', _, '01001') => __encoding aarch64_vector_arithmetic_binary_uniform_shift_simd 
					when ('0', _, '01010') => __encoding aarch64_vector_arithmetic_binary_uniform_shift_simd 
					when ('0', _, '01011') => __encoding aarch64_vector_arithmetic_binary_uniform_shift_simd 
					when ('0', _, '01100') => __encoding aarch64_vector_arithmetic_binary_uniform_max_min_single 
					when ('0', _, '01101') => __encoding aarch64_vector_arithmetic_binary_uniform_max_min_single 
					when ('0', _, '01110') => __encoding aarch64_vector_arithmetic_binary_uniform_diff 
					when ('0', _, '01111') => __encoding aarch64_vector_arithmetic_binary_uniform_diff 
					when ('0', _, '10000') => __encoding aarch64_vector_arithmetic_binary_uniform_add_wrapping_single_simd 
					when ('0', _, '10001') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_bitwise_simd 
					when ('0', _, '10010') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_int_accum 
					when ('0', _, '10011') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_int_product 
					when ('0', _, '10100') => __encoding aarch64_vector_arithmetic_binary_uniform_max_min_pair 
					when ('0', _, '10101') => __encoding aarch64_vector_arithmetic_binary_uniform_max_min_pair 
					when ('0', _, '10110') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_int_doubling_simd 
					when ('0', _, '10111') => __encoding aarch64_vector_arithmetic_binary_uniform_add_wrapping_pair 
					when ('0', '0x', '11000') => __encoding aarch64_vector_arithmetic_binary_uniform_max_min_fp_2008 
					when ('0', '0x', '11001') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_fp_fused 
					when ('0', '0x', '11010') => __encoding aarch64_vector_arithmetic_binary_uniform_add_fp 
					when ('0', '0x', '11011') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_fp_extended_simd 
					when ('0', '0x', '11100') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_fp_simd 
					when ('0', '0x', '11110') => __encoding aarch64_vector_arithmetic_binary_uniform_max_min_fp_1985 
					when ('0', '0x', '11111') => __encoding aarch64_vector_arithmetic_binary_uniform_recps_simd 
					when ('0', '00', '00011') => __encoding aarch64_vector_arithmetic_binary_uniform_logical_and_orr 
					when ('0', '00', '11101') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_fp_mul_norounding_lower 
					when ('0', '01', '00011') => __encoding aarch64_vector_arithmetic_binary_uniform_logical_and_orr 
					when ('0', '01', '11101') => __UNALLOCATED
					when ('0', '1x', '11000') => __encoding aarch64_vector_arithmetic_binary_uniform_max_min_fp_2008 
					when ('0', '1x', '11001') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_fp_fused 
					when ('0', '1x', '11010') => __encoding aarch64_vector_arithmetic_binary_uniform_sub_fp_simd 
					when ('0', '1x', '11011') => __UNALLOCATED
					when ('0', '1x', '11100') => __UNALLOCATED
					when ('0', '1x', '11110') => __encoding aarch64_vector_arithmetic_binary_uniform_max_min_fp_1985 
					when ('0', '1x', '11111') => __encoding aarch64_vector_arithmetic_binary_uniform_rsqrts_simd 
					when ('0', '10', '00011') => __encoding aarch64_vector_arithmetic_binary_uniform_logical_and_orr 
					when ('0', '10', '11101') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_fp_mul_norounding_lower 
					when ('0', '11', '00011') => __encoding aarch64_vector_arithmetic_binary_uniform_logical_and_orr 
					when ('0', '11', '11101') => __UNALLOCATED
					when ('1', _, '00000') => __encoding aarch64_vector_arithmetic_binary_uniform_add_halving_truncating 
					when ('1', _, '00001') => __encoding aarch64_vector_arithmetic_binary_uniform_add_saturating_simd 
					when ('1', _, '00010') => __encoding aarch64_vector_arithmetic_binary_uniform_add_halving_rounding 
					when ('1', _, '00100') => __encoding aarch64_vector_arithmetic_binary_uniform_sub_int 
					when ('1', _, '00101') => __encoding aarch64_vector_arithmetic_binary_uniform_sub_saturating_simd 
					when ('1', _, '00110') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_int_simd 
					when ('1', _, '00111') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_int_simd 
					when ('1', _, '01000') => __encoding aarch64_vector_arithmetic_binary_uniform_shift_simd 
					when ('1', _, '01001') => __encoding aarch64_vector_arithmetic_binary_uniform_shift_simd 
					when ('1', _, '01010') => __encoding aarch64_vector_arithmetic_binary_uniform_shift_simd 
					when ('1', _, '01011') => __encoding aarch64_vector_arithmetic_binary_uniform_shift_simd 
					when ('1', _, '01100') => __encoding aarch64_vector_arithmetic_binary_uniform_max_min_single 
					when ('1', _, '01101') => __encoding aarch64_vector_arithmetic_binary_uniform_max_min_single 
					when ('1', _, '01110') => __encoding aarch64_vector_arithmetic_binary_uniform_diff 
					when ('1', _, '01111') => __encoding aarch64_vector_arithmetic_binary_uniform_diff 
					when ('1', _, '10000') => __encoding aarch64_vector_arithmetic_binary_uniform_add_wrapping_single_simd 
					when ('1', _, '10001') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_bitwise_simd 
					when ('1', _, '10010') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_int_accum 
					when ('1', _, '10011') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_int_product 
					when ('1', _, '10100') => __encoding aarch64_vector_arithmetic_binary_uniform_max_min_pair 
					when ('1', _, '10101') => __encoding aarch64_vector_arithmetic_binary_uniform_max_min_pair 
					when ('1', _, '10110') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_int_doubling_simd 
					when ('1', _, '10111') => __UNALLOCATED
					when ('1', '0x', '11000') => __encoding aarch64_vector_arithmetic_binary_uniform_max_min_fp_2008 
					when ('1', '0x', '11010') => __encoding aarch64_vector_arithmetic_binary_uniform_add_fp 
					when ('1', '0x', '11011') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_fp_product 
					when ('1', '0x', '11100') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_fp_simd 
					when ('1', '0x', '11101') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_fp_simd 
					when ('1', '0x', '11110') => __encoding aarch64_vector_arithmetic_binary_uniform_max_min_fp_1985 
					when ('1', '0x', '11111') => __encoding aarch64_vector_arithmetic_binary_uniform_div 
					when ('1', '00', '00011') => __encoding aarch64_vector_arithmetic_binary_uniform_logical_bsl_eor 
					when ('1', '00', '11001') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_fp_mul_norounding_upper 
					when ('1', '01', '00011') => __encoding aarch64_vector_arithmetic_binary_uniform_logical_bsl_eor 
					when ('1', '01', '11001') => __UNALLOCATED
					when ('1', '1x', '11000') => __encoding aarch64_vector_arithmetic_binary_uniform_max_min_fp_2008 
					when ('1', '1x', '11010') => __encoding aarch64_vector_arithmetic_binary_uniform_sub_fp_simd 
					when ('1', '1x', '11011') => __UNALLOCATED
					when ('1', '1x', '11100') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_fp_simd 
					when ('1', '1x', '11101') => __encoding aarch64_vector_arithmetic_binary_uniform_cmp_fp_simd 
					when ('1', '1x', '11110') => __encoding aarch64_vector_arithmetic_binary_uniform_max_min_fp_1985 
					when ('1', '1x', '11111') => __UNALLOCATED
					when ('1', '10', '00011') => __encoding aarch64_vector_arithmetic_binary_uniform_logical_bsl_eor 
					when ('1', '10', '11001') => __encoding aarch64_vector_arithmetic_binary_uniform_mul_fp_mul_norounding_upper 
					when ('1', '11', '00011') => __encoding aarch64_vector_arithmetic_binary_uniform_logical_bsl_eor 
					when ('1', '11', '11001') => __UNALLOCATED
			when ('0xx0', _, '10', '0000', 'xxxxxxxx1', _) => 
				__field Q 30 +: 1
				__field op 29 +: 1
				__field a 18 +: 1
				__field b 17 +: 1
				__field c 16 +: 1
				__field cmode 12 +: 4
				__field o2 11 +: 1
				__field d 9 +: 1
				__field e 8 +: 1
				__field f 7 +: 1
				__field g 6 +: 1
				__field h 5 +: 1
				__field Rd 0 +: 5
				case (Q, op, cmode, o2) of
					when (_, '0', '0xxx', '1') => __UNALLOCATED
					when (_, '0', '0xx0', '0') => __encoding aarch64_vector_logical 
					when (_, '0', '0xx1', '0') => __encoding aarch64_vector_logical 
					when (_, '0', '10xx', '1') => __UNALLOCATED
					when (_, '0', '10x0', '0') => __encoding aarch64_vector_logical 
					when (_, '0', '10x1', '0') => __encoding aarch64_vector_logical 
					when (_, '0', '110x', '0') => __encoding aarch64_vector_logical 
					when (_, '0', '110x', '1') => __UNALLOCATED
					when (_, '0', '1110', '0') => __encoding aarch64_vector_logical 
					when (_, '0', '1110', '1') => __UNALLOCATED
					when (_, '0', '1111', '0') => __encoding aarch64_vector_logical 
					when (_, '0', '1111', '1') => __encoding aarch64_vector_fp16_movi 
					when (_, '1', _, '1') => __UNALLOCATED
					when (_, '1', '0xx0', '0') => __encoding aarch64_vector_logical 
					when (_, '1', '0xx1', '0') => __encoding aarch64_vector_logical 
					when (_, '1', '10x0', '0') => __encoding aarch64_vector_logical 
					when (_, '1', '10x1', '0') => __encoding aarch64_vector_logical 
					when (_, '1', '110x', '0') => __encoding aarch64_vector_logical 
					when ('0', '1', '1110', '0') => __encoding aarch64_vector_logical 
					when ('0', '1', '1111', '0') => __UNALLOCATED
					when ('1', '1', '1110', '0') => __encoding aarch64_vector_logical 
					when ('1', '1', '1111', '0') => __encoding aarch64_vector_logical 
			when ('0xx0', _, '10', !'0000', 'xxxxxxxx1', _) => 
				__field Q 30 +: 1
				__field U 29 +: 1
				__field immh 19 +: 4
				__field immb 16 +: 3
				__field opcode 11 +: 5
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (U, opcode) of
					when (_, '00001') => __UNALLOCATED
					when (_, '00011') => __UNALLOCATED
					when (_, '00101') => __UNALLOCATED
					when (_, '00111') => __UNALLOCATED
					when (_, '01001') => __UNALLOCATED
					when (_, '01011') => __UNALLOCATED
					when (_, '01101') => __UNALLOCATED
					when (_, '01111') => __UNALLOCATED
					when (_, '10101') => __UNALLOCATED
					when (_, '1011x') => __UNALLOCATED
					when (_, '110xx') => __UNALLOCATED
					when (_, '11101') => __UNALLOCATED
					when (_, '11110') => __UNALLOCATED
					when ('0', '00000') => __encoding aarch64_vector_shift_right_simd 
					when ('0', '00010') => __encoding aarch64_vector_shift_right_simd 
					when ('0', '00100') => __encoding aarch64_vector_shift_right_simd 
					when ('0', '00110') => __encoding aarch64_vector_shift_right_simd 
					when ('0', '01000') => __UNALLOCATED
					when ('0', '01010') => __encoding aarch64_vector_shift_left_simd 
					when ('0', '01100') => __UNALLOCATED
					when ('0', '01110') => __encoding aarch64_vector_shift_left_sat_simd 
					when ('0', '10000') => __encoding aarch64_vector_shift_right_narrow_logical 
					when ('0', '10001') => __encoding aarch64_vector_shift_right_narrow_logical 
					when ('0', '10010') => __encoding aarch64_vector_shift_right_narrow_uniform_simd 
					when ('0', '10011') => __encoding aarch64_vector_shift_right_narrow_uniform_simd 
					when ('0', '10100') => __encoding aarch64_vector_shift_left_long 
					when ('0', '11100') => __encoding aarch64_vector_shift_conv_int_simd 
					when ('0', '11111') => __encoding aarch64_vector_shift_conv_float_simd 
					when ('1', '00000') => __encoding aarch64_vector_shift_right_simd 
					when ('1', '00010') => __encoding aarch64_vector_shift_right_simd 
					when ('1', '00100') => __encoding aarch64_vector_shift_right_simd 
					when ('1', '00110') => __encoding aarch64_vector_shift_right_simd 
					when ('1', '01000') => __encoding aarch64_vector_shift_right_insert_simd 
					when ('1', '01010') => __encoding aarch64_vector_shift_left_insert_simd 
					when ('1', '01100') => __encoding aarch64_vector_shift_left_sat_simd 
					when ('1', '01110') => __encoding aarch64_vector_shift_left_sat_simd 
					when ('1', '10000') => __encoding aarch64_vector_shift_right_narrow_nonuniform_simd 
					when ('1', '10001') => __encoding aarch64_vector_shift_right_narrow_nonuniform_simd 
					when ('1', '10010') => __encoding aarch64_vector_shift_right_narrow_uniform_simd 
					when ('1', '10011') => __encoding aarch64_vector_shift_right_narrow_uniform_simd 
					when ('1', '10100') => __encoding aarch64_vector_shift_left_long 
					when ('1', '11100') => __encoding aarch64_vector_shift_conv_int_simd 
					when ('1', '11111') => __encoding aarch64_vector_shift_conv_float_simd 
			when ('0xx0', _, '11', _, 'xxxxxxxx1', _) => __UNPREDICTABLE
			when ('0xx0', _, '1x', _, 'xxxxxxxx0', _) => 
				__field Q 30 +: 1
				__field U 29 +: 1
				__field size 22 +: 2
				__field L 21 +: 1
				__field M 20 +: 1
				__field Rm 16 +: 4
				__field opcode 12 +: 4
				__field H 11 +: 1
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (U, size, opcode) of
					when (_, '01', '1001') => __UNALLOCATED
					when ('0', _, '0010') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_long 
					when ('0', _, '0011') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_double_simd 
					when ('0', _, '0110') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_long 
					when ('0', _, '0111') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_double_simd 
					when ('0', _, '1000') => __encoding aarch64_vector_arithmetic_binary_element_mul_int 
					when ('0', _, '1010') => __encoding aarch64_vector_arithmetic_binary_element_mul_long 
					when ('0', _, '1011') => __encoding aarch64_vector_arithmetic_binary_element_mul_double_simd 
					when ('0', _, '1100') => __encoding aarch64_vector_arithmetic_binary_element_mul_high_simd 
					when ('0', _, '1101') => __encoding aarch64_vector_arithmetic_binary_element_mul_high_simd 
					when ('0', _, '1110') => __encoding aarch64_vector_arithmetic_binary_element_dotp 
					when ('0', '0x', '0000') => __UNALLOCATED
					when ('0', '0x', '0100') => __UNALLOCATED
					when ('0', '00', '0001') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_fp16_simd 
					when ('0', '00', '0101') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_fp16_simd 
					when ('0', '00', '1001') => __encoding aarch64_vector_arithmetic_binary_element_mul_fp16_simd 
					when ('0', '00', '1111') => __encoding aarch64_vector_arithmetic_binary_element_mat_mul_int_dotp 
					when ('0', '01', '0001') => __UNALLOCATED
					when ('0', '01', '0101') => __UNALLOCATED
					when ('0', '01', '1111') => __encoding aarch64_vector_arithmetic_binary_element_bfdot 
					when ('0', '1x', '0001') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_fp_simd 
					when ('0', '1x', '0101') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_fp_simd 
					when ('0', '1x', '1001') => __encoding aarch64_vector_arithmetic_binary_element_mul_fp_simd 
					when ('0', '10', '0000') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_mul_norounding_i_lower 
					when ('0', '10', '0100') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_mul_norounding_i_lower 
					when ('0', '10', '1111') => __encoding aarch64_vector_arithmetic_binary_element_mat_mul_int_dotp 
					when ('0', '11', '0000') => __UNALLOCATED
					when ('0', '11', '0100') => __UNALLOCATED
					when ('0', '11', '1111') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_bf16_long 
					when ('1', _, '0000') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_int 
					when ('1', _, '0010') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_long 
					when ('1', _, '0100') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_int 
					when ('1', _, '0110') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_long 
					when ('1', _, '1010') => __encoding aarch64_vector_arithmetic_binary_element_mul_long 
					when ('1', _, '1011') => __UNALLOCATED
					when ('1', _, '1101') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_high_simd 
					when ('1', _, '1110') => __encoding aarch64_vector_arithmetic_binary_element_dotp 
					when ('1', _, '1111') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_high_simd 
					when ('1', '0x', '1000') => __UNALLOCATED
					when ('1', '0x', '1100') => __UNALLOCATED
					when ('1', '00', '0001') => __UNALLOCATED
					when ('1', '00', '0011') => __UNALLOCATED
					when ('1', '00', '0101') => __UNALLOCATED
					when ('1', '00', '0111') => __UNALLOCATED
					when ('1', '00', '1001') => __encoding aarch64_vector_arithmetic_binary_element_mul_fp16_simd 
					when ('1', '01', '0xx1') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_complex 
					when ('1', '1x', '1001') => __encoding aarch64_vector_arithmetic_binary_element_mul_fp_simd 
					when ('1', '10', '0xx1') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_complex 
					when ('1', '10', '1000') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_mul_norounding_i_upper 
					when ('1', '10', '1100') => __encoding aarch64_vector_arithmetic_binary_element_mul_acc_mul_norounding_i_upper 
					when ('1', '11', '0001') => __UNALLOCATED
					when ('1', '11', '0011') => __UNALLOCATED
					when ('1', '11', '0101') => __UNALLOCATED
					when ('1', '11', '0111') => __UNALLOCATED
					when ('1', '11', '1000') => __UNALLOCATED
					when ('1', '11', '1100') => __UNALLOCATED
			when ('1100', _, '00', '10xx', 'xxx10xxxx', _) => 
				__field Rm 16 +: 5
				__field imm2 12 +: 2
				__field opcode 10 +: 2
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (opcode) of
					when ('00') => __encoding aarch64_vector_crypto_sm3_sm3tt1a 
					when ('01') => __encoding aarch64_vector_crypto_sm3_sm3tt1b 
					when ('10') => __encoding aarch64_vector_crypto_sm3_sm3tt2a 
					when ('11') => __encoding aarch64_vector_crypto_sm3_sm3tt2b 
			when ('1100', _, '00', '11xx', 'xxx1x00xx', _) => 
				__field Rm 16 +: 5
				__field O 14 +: 1
				__field opcode 10 +: 2
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (O, opcode) of
					when ('0', '00') => __encoding aarch64_vector_crypto_sha512_sha512h 
					when ('0', '01') => __encoding aarch64_vector_crypto_sha512_sha512h2 
					when ('0', '10') => __encoding aarch64_vector_crypto_sha512_sha512su1 
					when ('0', '11') => __encoding aarch64_vector_crypto_sha3_rax1 
					when ('1', '00') => __encoding aarch64_vector_crypto_sm3_sm3partw1 
					when ('1', '01') => __encoding aarch64_vector_crypto_sm3_sm3partw2 
					when ('1', '10') => __encoding aarch64_vector_crypto_sm4_sm4enckey 
					when ('1', '11') => __UNALLOCATED
			when ('1100', _, '00', _, 'xxx0xxxxx', _) => 
				__field Op0 21 +: 2
				__field Rm 16 +: 5
				__field Ra 10 +: 5
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (Op0) of
					when ('00') => __encoding aarch64_vector_crypto_sha3_eor3 
					when ('01') => __encoding aarch64_vector_crypto_sha3_bcax 
					when ('10') => __encoding aarch64_vector_crypto_sm3_sm3ss1 
					when ('11') => __UNALLOCATED
			when ('1100', _, '01', '00xx', _, _) => 
				__field Rm 16 +: 5
				__field imm6 10 +: 6
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case () of
					when () => __encoding aarch64_vector_crypto_sha3_xar 
			when ('1100', _, '01', '1000', '0001000xx', _) => 
				__field opcode 10 +: 2
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (opcode) of
					when ('00') => __encoding aarch64_vector_crypto_sha512_sha512su0 
					when ('01') => __encoding aarch64_vector_crypto_sm4_sm4enc 
					when ('1x') => __UNALLOCATED
			when ('1xx0', _, '1x', _, _, _) => __UNPREDICTABLE
			when ('x0x1', _, '0x', 'x0xx', _, _) => 
				__field sf 31 +: 1
				__field S 29 +: 1
				__field ptype 22 +: 2
				__field rmode 19 +: 2
				__field opcode 16 +: 3
				__field scale 10 +: 6
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (sf, S, ptype, rmode, opcode, scale) of
					when (_, _, _, _, '1xx', _) => __UNALLOCATED
					when (_, _, _, 'x0', '00x', _) => __UNALLOCATED
					when (_, _, _, 'x1', '01x', _) => __UNALLOCATED
					when (_, _, _, '0x', '00x', _) => __UNALLOCATED
					when (_, _, _, '1x', '01x', _) => __UNALLOCATED
					when (_, _, '10', _, _, _) => __UNALLOCATED
					when (_, '1', _, _, _, _) => __UNALLOCATED
					when ('0', _, _, _, _, '0xxxxx') => __UNALLOCATED
					when ('0', '0', '00', '00', '010', _) => __encoding aarch64_float_convert_fix 
					when ('0', '0', '00', '00', '011', _) => __encoding aarch64_float_convert_fix 
					when ('0', '0', '00', '11', '000', _) => __encoding aarch64_float_convert_fix 
					when ('0', '0', '00', '11', '001', _) => __encoding aarch64_float_convert_fix 
					when ('0', '0', '01', '00', '010', _) => __encoding aarch64_float_convert_fix 
					when ('0', '0', '01', '00', '011', _) => __encoding aarch64_float_convert_fix 
					when ('0', '0', '01', '11', '000', _) => __encoding aarch64_float_convert_fix 
					when ('0', '0', '01', '11', '001', _) => __encoding aarch64_float_convert_fix 
					when ('0', '0', '11', '00', '010', _) => __encoding aarch64_float_convert_fix 
					when ('0', '0', '11', '00', '011', _) => __encoding aarch64_float_convert_fix 
					when ('0', '0', '11', '11', '000', _) => __encoding aarch64_float_convert_fix 
					when ('0', '0', '11', '11', '001', _) => __encoding aarch64_float_convert_fix 
					when ('1', '0', '00', '00', '010', _) => __encoding aarch64_float_convert_fix 
					when ('1', '0', '00', '00', '011', _) => __encoding aarch64_float_convert_fix 
					when ('1', '0', '00', '11', '000', _) => __encoding aarch64_float_convert_fix 
					when ('1', '0', '00', '11', '001', _) => __encoding aarch64_float_convert_fix 
					when ('1', '0', '01', '00', '010', _) => __encoding aarch64_float_convert_fix 
					when ('1', '0', '01', '00', '011', _) => __encoding aarch64_float_convert_fix 
					when ('1', '0', '01', '11', '000', _) => __encoding aarch64_float_convert_fix 
					when ('1', '0', '01', '11', '001', _) => __encoding aarch64_float_convert_fix 
					when ('1', '0', '11', '00', '010', _) => __encoding aarch64_float_convert_fix 
					when ('1', '0', '11', '00', '011', _) => __encoding aarch64_float_convert_fix 
					when ('1', '0', '11', '11', '000', _) => __encoding aarch64_float_convert_fix 
					when ('1', '0', '11', '11', '001', _) => __encoding aarch64_float_convert_fix 
			when ('x0x1', _, '0x', 'x1xx', 'xxx000000', _) => 
				__field sf 31 +: 1
				__field S 29 +: 1
				__field ptype 22 +: 2
				__field rmode 19 +: 2
				__field opcode 16 +: 3
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (sf, S, ptype, rmode, opcode) of
					when (_, _, _, 'x1', '01x') => __UNALLOCATED
					when (_, _, _, 'x1', '10x') => __UNALLOCATED
					when (_, _, _, '1x', '01x') => __UNALLOCATED
					when (_, _, _, '1x', '10x') => __UNALLOCATED
					when (_, '0', '10', _, '0xx') => __UNALLOCATED
					when (_, '0', '10', _, '10x') => __UNALLOCATED
					when (_, '1', _, _, _) => __UNALLOCATED
					when ('0', '0', '00', 'x1', '11x') => __UNALLOCATED
					when ('0', '0', '00', '00', '000') => __encoding aarch64_float_convert_int 
					when ('0', '0', '00', '00', '001') => __encoding aarch64_float_convert_int 
					when ('0', '0', '00', '00', '010') => __encoding aarch64_float_convert_int 
					when ('0', '0', '00', '00', '011') => __encoding aarch64_float_convert_int 
					when ('0', '0', '00', '00', '100') => __encoding aarch64_float_convert_int 
					when ('0', '0', '00', '00', '101') => __encoding aarch64_float_convert_int 
					when ('0', '0', '00', '00', '110') => __encoding aarch64_float_convert_int 
					when ('0', '0', '00', '00', '111') => __encoding aarch64_float_convert_int 
					when ('0', '0', '00', '01', '000') => __encoding aarch64_float_convert_int 
					when ('0', '0', '00', '01', '001') => __encoding aarch64_float_convert_int 
					when ('0', '0', '00', '1x', '11x') => __UNALLOCATED
					when ('0', '0', '00', '10', '000') => __encoding aarch64_float_convert_int 
					when ('0', '0', '00', '10', '001') => __encoding aarch64_float_convert_int 
					when ('0', '0', '00', '11', '000') => __encoding aarch64_float_convert_int 
					when ('0', '0', '00', '11', '001') => __encoding aarch64_float_convert_int 
					when ('0', '0', '01', '0x', '11x') => __UNALLOCATED
					when ('0', '0', '01', '00', '000') => __encoding aarch64_float_convert_int 
					when ('0', '0', '01', '00', '001') => __encoding aarch64_float_convert_int 
					when ('0', '0', '01', '00', '010') => __encoding aarch64_float_convert_int 
					when ('0', '0', '01', '00', '011') => __encoding aarch64_float_convert_int 
					when ('0', '0', '01', '00', '100') => __encoding aarch64_float_convert_int 
					when ('0', '0', '01', '00', '101') => __encoding aarch64_float_convert_int 
					when ('0', '0', '01', '01', '000') => __encoding aarch64_float_convert_int 
					when ('0', '0', '01', '01', '001') => __encoding aarch64_float_convert_int 
					when ('0', '0', '01', '10', '000') => __encoding aarch64_float_convert_int 
					when ('0', '0', '01', '10', '001') => __encoding aarch64_float_convert_int 
					when ('0', '0', '01', '10', '11x') => __UNALLOCATED
					when ('0', '0', '01', '11', '000') => __encoding aarch64_float_convert_int 
					when ('0', '0', '01', '11', '001') => __encoding aarch64_float_convert_int 
					when ('0', '0', '01', '11', '110') => __encoding aarch64_float_convert_int 
					when ('0', '0', '01', '11', '111') => __UNALLOCATED
					when ('0', '0', '10', _, '11x') => __UNALLOCATED
					when ('0', '0', '11', '00', '000') => __encoding aarch64_float_convert_int 
					when ('0', '0', '11', '00', '001') => __encoding aarch64_float_convert_int 
					when ('0', '0', '11', '00', '010') => __encoding aarch64_float_convert_int 
					when ('0', '0', '11', '00', '011') => __encoding aarch64_float_convert_int 
					when ('0', '0', '11', '00', '100') => __encoding aarch64_float_convert_int 
					when ('0', '0', '11', '00', '101') => __encoding aarch64_float_convert_int 
					when ('0', '0', '11', '00', '110') => __encoding aarch64_float_convert_int 
					when ('0', '0', '11', '00', '111') => __encoding aarch64_float_convert_int 
					when ('0', '0', '11', '01', '000') => __encoding aarch64_float_convert_int 
					when ('0', '0', '11', '01', '001') => __encoding aarch64_float_convert_int 
					when ('0', '0', '11', '10', '000') => __encoding aarch64_float_convert_int 
					when ('0', '0', '11', '10', '001') => __encoding aarch64_float_convert_int 
					when ('0', '0', '11', '11', '000') => __encoding aarch64_float_convert_int 
					when ('0', '0', '11', '11', '001') => __encoding aarch64_float_convert_int 
					when ('1', '0', '00', _, '11x') => __UNALLOCATED
					when ('1', '0', '00', '00', '000') => __encoding aarch64_float_convert_int 
					when ('1', '0', '00', '00', '001') => __encoding aarch64_float_convert_int 
					when ('1', '0', '00', '00', '010') => __encoding aarch64_float_convert_int 
					when ('1', '0', '00', '00', '011') => __encoding aarch64_float_convert_int 
					when ('1', '0', '00', '00', '100') => __encoding aarch64_float_convert_int 
					when ('1', '0', '00', '00', '101') => __encoding aarch64_float_convert_int 
					when ('1', '0', '00', '01', '000') => __encoding aarch64_float_convert_int 
					when ('1', '0', '00', '01', '001') => __encoding aarch64_float_convert_int 
					when ('1', '0', '00', '10', '000') => __encoding aarch64_float_convert_int 
					when ('1', '0', '00', '10', '001') => __encoding aarch64_float_convert_int 
					when ('1', '0', '00', '11', '000') => __encoding aarch64_float_convert_int 
					when ('1', '0', '00', '11', '001') => __encoding aarch64_float_convert_int 
					when ('1', '0', '01', 'x1', '11x') => __UNALLOCATED
					when ('1', '0', '01', '00', '000') => __encoding aarch64_float_convert_int 
					when ('1', '0', '01', '00', '001') => __encoding aarch64_float_convert_int 
					when ('1', '0', '01', '00', '010') => __encoding aarch64_float_convert_int 
					when ('1', '0', '01', '00', '011') => __encoding aarch64_float_convert_int 
					when ('1', '0', '01', '00', '100') => __encoding aarch64_float_convert_int 
					when ('1', '0', '01', '00', '101') => __encoding aarch64_float_convert_int 
					when ('1', '0', '01', '00', '110') => __encoding aarch64_float_convert_int 
					when ('1', '0', '01', '00', '111') => __encoding aarch64_float_convert_int 
					when ('1', '0', '01', '01', '000') => __encoding aarch64_float_convert_int 
					when ('1', '0', '01', '01', '001') => __encoding aarch64_float_convert_int 
					when ('1', '0', '01', '1x', '11x') => __UNALLOCATED
					when ('1', '0', '01', '10', '000') => __encoding aarch64_float_convert_int 
					when ('1', '0', '01', '10', '001') => __encoding aarch64_float_convert_int 
					when ('1', '0', '01', '11', '000') => __encoding aarch64_float_convert_int 
					when ('1', '0', '01', '11', '001') => __encoding aarch64_float_convert_int 
					when ('1', '0', '10', 'x0', '11x') => __UNALLOCATED
					when ('1', '0', '10', '01', '110') => __encoding aarch64_float_convert_int 
					when ('1', '0', '10', '01', '111') => __encoding aarch64_float_convert_int 
					when ('1', '0', '10', '1x', '11x') => __UNALLOCATED
					when ('1', '0', '11', '00', '000') => __encoding aarch64_float_convert_int 
					when ('1', '0', '11', '00', '001') => __encoding aarch64_float_convert_int 
					when ('1', '0', '11', '00', '010') => __encoding aarch64_float_convert_int 
					when ('1', '0', '11', '00', '011') => __encoding aarch64_float_convert_int 
					when ('1', '0', '11', '00', '100') => __encoding aarch64_float_convert_int 
					when ('1', '0', '11', '00', '101') => __encoding aarch64_float_convert_int 
					when ('1', '0', '11', '00', '110') => __encoding aarch64_float_convert_int 
					when ('1', '0', '11', '00', '111') => __encoding aarch64_float_convert_int 
					when ('1', '0', '11', '01', '000') => __encoding aarch64_float_convert_int 
					when ('1', '0', '11', '01', '001') => __encoding aarch64_float_convert_int 
					when ('1', '0', '11', '10', '000') => __encoding aarch64_float_convert_int 
					when ('1', '0', '11', '10', '001') => __encoding aarch64_float_convert_int 
					when ('1', '0', '11', '11', '000') => __encoding aarch64_float_convert_int 
					when ('1', '0', '11', '11', '001') => __encoding aarch64_float_convert_int 
			when ('x0x1', _, '0x', 'x1xx', 'xxxx10000', _) => 
				__field M 31 +: 1
				__field S 29 +: 1
				__field ptype 22 +: 2
				__field opcode 15 +: 6
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (M, S, ptype, opcode) of
					when (_, _, _, '1xxxxx') => __UNALLOCATED
					when (_, '1', _, _) => __UNALLOCATED
					when ('0', '0', '00', '000000') => __encoding aarch64_float_arithmetic_unary 
					when ('0', '0', '00', '000001') => __encoding aarch64_float_arithmetic_unary 
					when ('0', '0', '00', '000010') => __encoding aarch64_float_arithmetic_unary 
					when ('0', '0', '00', '000011') => __encoding aarch64_float_arithmetic_unary 
					when ('0', '0', '00', '000100') => __UNALLOCATED
					when ('0', '0', '00', '000101') => __encoding aarch64_float_convert_fp 
					when ('0', '0', '00', '000110') => __UNALLOCATED
					when ('0', '0', '00', '000111') => __encoding aarch64_float_convert_fp 
					when ('0', '0', '00', '001000') => __encoding aarch64_float_arithmetic_round_frint 
					when ('0', '0', '00', '001001') => __encoding aarch64_float_arithmetic_round_frint 
					when ('0', '0', '00', '001010') => __encoding aarch64_float_arithmetic_round_frint 
					when ('0', '0', '00', '001011') => __encoding aarch64_float_arithmetic_round_frint 
					when ('0', '0', '00', '001100') => __encoding aarch64_float_arithmetic_round_frint 
					when ('0', '0', '00', '001101') => __UNALLOCATED
					when ('0', '0', '00', '001110') => __encoding aarch64_float_arithmetic_round_frint 
					when ('0', '0', '00', '001111') => __encoding aarch64_float_arithmetic_round_frint 
					when ('0', '0', '00', '010000') => __encoding aarch64_float_arithmetic_round_frint_32_64 
					when ('0', '0', '00', '010001') => __encoding aarch64_float_arithmetic_round_frint_32_64 
					when ('0', '0', '00', '010010') => __encoding aarch64_float_arithmetic_round_frint_32_64 
					when ('0', '0', '00', '010011') => __encoding aarch64_float_arithmetic_round_frint_32_64 
					when ('0', '0', '00', '0101xx') => __UNALLOCATED
					when ('0', '0', '00', '011xxx') => __UNALLOCATED
					when ('0', '0', '01', '000000') => __encoding aarch64_float_arithmetic_unary 
					when ('0', '0', '01', '000001') => __encoding aarch64_float_arithmetic_unary 
					when ('0', '0', '01', '000010') => __encoding aarch64_float_arithmetic_unary 
					when ('0', '0', '01', '000011') => __encoding aarch64_float_arithmetic_unary 
					when ('0', '0', '01', '000100') => __encoding aarch64_float_convert_fp 
					when ('0', '0', '01', '000101') => __UNALLOCATED
					when ('0', '0', '01', '000110') => __encoding aarch64_vector_cvt_bf16_scalar 
					when ('0', '0', '01', '000111') => __encoding aarch64_float_convert_fp 
					when ('0', '0', '01', '001000') => __encoding aarch64_float_arithmetic_round_frint 
					when ('0', '0', '01', '001001') => __encoding aarch64_float_arithmetic_round_frint 
					when ('0', '0', '01', '001010') => __encoding aarch64_float_arithmetic_round_frint 
					when ('0', '0', '01', '001011') => __encoding aarch64_float_arithmetic_round_frint 
					when ('0', '0', '01', '001100') => __encoding aarch64_float_arithmetic_round_frint 
					when ('0', '0', '01', '001101') => __UNALLOCATED
					when ('0', '0', '01', '001110') => __encoding aarch64_float_arithmetic_round_frint 
					when ('0', '0', '01', '001111') => __encoding aarch64_float_arithmetic_round_frint 
					when ('0', '0', '01', '010000') => __encoding aarch64_float_arithmetic_round_frint_32_64 
					when ('0', '0', '01', '010001') => __encoding aarch64_float_arithmetic_round_frint_32_64 
					when ('0', '0', '01', '010010') => __encoding aarch64_float_arithmetic_round_frint_32_64 
					when ('0', '0', '01', '010011') => __encoding aarch64_float_arithmetic_round_frint_32_64 
					when ('0', '0', '01', '0101xx') => __UNALLOCATED
					when ('0', '0', '01', '011xxx') => __UNALLOCATED
					when ('0', '0', '10', '0xxxxx') => __UNALLOCATED
					when ('0', '0', '11', '000000') => __encoding aarch64_float_arithmetic_unary 
					when ('0', '0', '11', '000001') => __encoding aarch64_float_arithmetic_unary 
					when ('0', '0', '11', '000010') => __encoding aarch64_float_arithmetic_unary 
					when ('0', '0', '11', '000011') => __encoding aarch64_float_arithmetic_unary 
					when ('0', '0', '11', '000100') => __encoding aarch64_float_convert_fp 
					when ('0', '0', '11', '000101') => __encoding aarch64_float_convert_fp 
					when ('0', '0', '11', '00011x') => __UNALLOCATED
					when ('0', '0', '11', '001000') => __encoding aarch64_float_arithmetic_round_frint 
					when ('0', '0', '11', '001001') => __encoding aarch64_float_arithmetic_round_frint 
					when ('0', '0', '11', '001010') => __encoding aarch64_float_arithmetic_round_frint 
					when ('0', '0', '11', '001011') => __encoding aarch64_float_arithmetic_round_frint 
					when ('0', '0', '11', '001100') => __encoding aarch64_float_arithmetic_round_frint 
					when ('0', '0', '11', '001101') => __UNALLOCATED
					when ('0', '0', '11', '001110') => __encoding aarch64_float_arithmetic_round_frint 
					when ('0', '0', '11', '001111') => __encoding aarch64_float_arithmetic_round_frint 
					when ('0', '0', '11', '01xxxx') => __UNALLOCATED
					when ('1', _, _, _) => __UNALLOCATED
			when ('x0x1', _, '0x', 'x1xx', 'xxxxx1000', _) => 
				__field M 31 +: 1
				__field S 29 +: 1
				__field ptype 22 +: 2
				__field Rm 16 +: 5
				__field op 14 +: 2
				__field Rn 5 +: 5
				__field opcode2 0 +: 5
				case (M, S, ptype, op, opcode2) of
					when (_, _, _, _, 'xxxx1') => __UNALLOCATED
					when (_, _, _, _, 'xxx1x') => __UNALLOCATED
					when (_, _, _, _, 'xx1xx') => __UNALLOCATED
					when (_, _, _, 'x1', _) => __UNALLOCATED
					when (_, _, _, '1x', _) => __UNALLOCATED
					when (_, _, '10', _, _) => __UNALLOCATED
					when (_, '1', _, _, _) => __UNALLOCATED
					when ('0', '0', '00', '00', '00000') => __encoding aarch64_float_compare_uncond 
					when ('0', '0', '00', '00', '01000') => __encoding aarch64_float_compare_uncond 
					when ('0', '0', '00', '00', '10000') => __encoding aarch64_float_compare_uncond 
					when ('0', '0', '00', '00', '11000') => __encoding aarch64_float_compare_uncond 
					when ('0', '0', '01', '00', '00000') => __encoding aarch64_float_compare_uncond 
					when ('0', '0', '01', '00', '01000') => __encoding aarch64_float_compare_uncond 
					when ('0', '0', '01', '00', '10000') => __encoding aarch64_float_compare_uncond 
					when ('0', '0', '01', '00', '11000') => __encoding aarch64_float_compare_uncond 
					when ('0', '0', '11', '00', '00000') => __encoding aarch64_float_compare_uncond 
					when ('0', '0', '11', '00', '01000') => __encoding aarch64_float_compare_uncond 
					when ('0', '0', '11', '00', '10000') => __encoding aarch64_float_compare_uncond 
					when ('0', '0', '11', '00', '11000') => __encoding aarch64_float_compare_uncond 
					when ('1', _, _, _, _) => __UNALLOCATED
			when ('x0x1', _, '0x', 'x1xx', 'xxxxxx100', _) => 
				__field M 31 +: 1
				__field S 29 +: 1
				__field ptype 22 +: 2
				__field imm8 13 +: 8
				__field imm5 5 +: 5
				__field Rd 0 +: 5
				case (M, S, ptype, imm5) of
					when (_, _, _, 'xxxx1') => __UNALLOCATED
					when (_, _, _, 'xxx1x') => __UNALLOCATED
					when (_, _, _, 'xx1xx') => __UNALLOCATED
					when (_, _, _, 'x1xxx') => __UNALLOCATED
					when (_, _, _, '1xxxx') => __UNALLOCATED
					when (_, _, '10', _) => __UNALLOCATED
					when (_, '1', _, _) => __UNALLOCATED
					when ('0', '0', '00', '00000') => __encoding aarch64_float_move_fp_imm 
					when ('0', '0', '01', '00000') => __encoding aarch64_float_move_fp_imm 
					when ('0', '0', '11', '00000') => __encoding aarch64_float_move_fp_imm 
					when ('1', _, _, _) => __UNALLOCATED
			when ('x0x1', _, '0x', 'x1xx', 'xxxxxxx01', _) => 
				__field M 31 +: 1
				__field S 29 +: 1
				__field ptype 22 +: 2
				__field Rm 16 +: 5
				__field cond 12 +: 4
				__field Rn 5 +: 5
				__field op 4 +: 1
				__field nzcv 0 +: 4
				case (M, S, ptype, op) of
					when (_, _, '10', _) => __UNALLOCATED
					when (_, '1', _, _) => __UNALLOCATED
					when ('0', '0', '00', '0') => __encoding aarch64_float_compare_cond 
					when ('0', '0', '00', '1') => __encoding aarch64_float_compare_cond 
					when ('0', '0', '01', '0') => __encoding aarch64_float_compare_cond 
					when ('0', '0', '01', '1') => __encoding aarch64_float_compare_cond 
					when ('0', '0', '11', '0') => __encoding aarch64_float_compare_cond 
					when ('0', '0', '11', '1') => __encoding aarch64_float_compare_cond 
					when ('1', _, _, _) => __UNALLOCATED
			when ('x0x1', _, '0x', 'x1xx', 'xxxxxxx10', _) => 
				__field M 31 +: 1
				__field S 29 +: 1
				__field ptype 22 +: 2
				__field Rm 16 +: 5
				__field opcode 12 +: 4
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (M, S, ptype, opcode) of
					when (_, _, _, '1xx1') => __UNALLOCATED
					when (_, _, _, '1x1x') => __UNALLOCATED
					when (_, _, _, '11xx') => __UNALLOCATED
					when (_, _, '10', _) => __UNALLOCATED
					when (_, '1', _, _) => __UNALLOCATED
					when ('0', '0', '00', '0000') => __encoding aarch64_float_arithmetic_mul_product 
					when ('0', '0', '00', '0001') => __encoding aarch64_float_arithmetic_div 
					when ('0', '0', '00', '0010') => __encoding aarch64_float_arithmetic_add_sub 
					when ('0', '0', '00', '0011') => __encoding aarch64_float_arithmetic_add_sub 
					when ('0', '0', '00', '0100') => __encoding aarch64_float_arithmetic_max_min 
					when ('0', '0', '00', '0101') => __encoding aarch64_float_arithmetic_max_min 
					when ('0', '0', '00', '0110') => __encoding aarch64_float_arithmetic_max_min 
					when ('0', '0', '00', '0111') => __encoding aarch64_float_arithmetic_max_min 
					when ('0', '0', '00', '1000') => __encoding aarch64_float_arithmetic_mul_product 
					when ('0', '0', '01', '0000') => __encoding aarch64_float_arithmetic_mul_product 
					when ('0', '0', '01', '0001') => __encoding aarch64_float_arithmetic_div 
					when ('0', '0', '01', '0010') => __encoding aarch64_float_arithmetic_add_sub 
					when ('0', '0', '01', '0011') => __encoding aarch64_float_arithmetic_add_sub 
					when ('0', '0', '01', '0100') => __encoding aarch64_float_arithmetic_max_min 
					when ('0', '0', '01', '0101') => __encoding aarch64_float_arithmetic_max_min 
					when ('0', '0', '01', '0110') => __encoding aarch64_float_arithmetic_max_min 
					when ('0', '0', '01', '0111') => __encoding aarch64_float_arithmetic_max_min 
					when ('0', '0', '01', '1000') => __encoding aarch64_float_arithmetic_mul_product 
					when ('0', '0', '11', '0000') => __encoding aarch64_float_arithmetic_mul_product 
					when ('0', '0', '11', '0001') => __encoding aarch64_float_arithmetic_div 
					when ('0', '0', '11', '0010') => __encoding aarch64_float_arithmetic_add_sub 
					when ('0', '0', '11', '0011') => __encoding aarch64_float_arithmetic_add_sub 
					when ('0', '0', '11', '0100') => __encoding aarch64_float_arithmetic_max_min 
					when ('0', '0', '11', '0101') => __encoding aarch64_float_arithmetic_max_min 
					when ('0', '0', '11', '0110') => __encoding aarch64_float_arithmetic_max_min 
					when ('0', '0', '11', '0111') => __encoding aarch64_float_arithmetic_max_min 
					when ('0', '0', '11', '1000') => __encoding aarch64_float_arithmetic_mul_product 
					when ('1', _, _, _) => __UNALLOCATED
			when ('x0x1', _, '0x', 'x1xx', 'xxxxxxx11', _) => 
				__field M 31 +: 1
				__field S 29 +: 1
				__field ptype 22 +: 2
				__field Rm 16 +: 5
				__field cond 12 +: 4
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (M, S, ptype) of
					when (_, _, '10') => __UNALLOCATED
					when (_, '1', _) => __UNALLOCATED
					when ('0', '0', '00') => __encoding aarch64_float_move_fp_select 
					when ('0', '0', '01') => __encoding aarch64_float_move_fp_select 
					when ('0', '0', '11') => __encoding aarch64_float_move_fp_select 
					when ('1', _, _) => __UNALLOCATED
			when ('x0x1', _, '1x', _, _, _) => 
				__field M 31 +: 1
				__field S 29 +: 1
				__field ptype 22 +: 2
				__field o1 21 +: 1
				__field Rm 16 +: 5
				__field o0 15 +: 1
				__field Ra 10 +: 5
				__field Rn 5 +: 5
				__field Rd 0 +: 5
				case (M, S, ptype, o1, o0) of
					when (_, _, '10', _, _) => __UNALLOCATED
					when (_, '1', _, _, _) => __UNALLOCATED
					when ('0', '0', '00', '0', '0') => __encoding aarch64_float_arithmetic_mul_add_sub 
					when ('0', '0', '00', '0', '1') => __encoding aarch64_float_arithmetic_mul_add_sub 
					when ('0', '0', '00', '1', '0') => __encoding aarch64_float_arithmetic_mul_add_sub 
					when ('0', '0', '00', '1', '1') => __encoding aarch64_float_arithmetic_mul_add_sub 
					when ('0', '0', '01', '0', '0') => __encoding aarch64_float_arithmetic_mul_add_sub 
					when ('0', '0', '01', '0', '1') => __encoding aarch64_float_arithmetic_mul_add_sub 
					when ('0', '0', '01', '1', '0') => __encoding aarch64_float_arithmetic_mul_add_sub 
					when ('0', '0', '01', '1', '1') => __encoding aarch64_float_arithmetic_mul_add_sub 
					when ('0', '0', '11', '0', '0') => __encoding aarch64_float_arithmetic_mul_add_sub 
					when ('0', '0', '11', '0', '1') => __encoding aarch64_float_arithmetic_mul_add_sub 
					when ('0', '0', '11', '1', '0') => __encoding aarch64_float_arithmetic_mul_add_sub 
					when ('0', '0', '11', '1', '1') => __encoding aarch64_float_arithmetic_mul_add_sub 
					when ('1', _, _, _, _) => __UNALLOCATED