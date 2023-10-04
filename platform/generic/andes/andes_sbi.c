// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2023 Renesas Electronics Corp.
 *
 */
#include <andes/andes45.h>
#include <andes/andes_sbi.h>
#include <sbi/riscv_asm.h>
#include <sbi/riscv_io.h>
#include <sbi/sbi_error.h>

enum sbi_ext_andes_fid {
	SBI_EXT_ANDES_FID0 = 0, /* Reserved for future use */
	SBI_EXT_ANDES_IOCP_SW_WORKAROUND,
	SBI_EXT_RENESAS_RZFIVE_GET_MCACHE_CTL_STATUS,
	SBI_EXT_RENESAS_RZFIVE_GET_MMISC_CTL_STATUS,
	SBI_EXT_RENESAS_RZFIVE_READ_LM,
	SBI_EXT_RENESAS_RZFIVE_WRITE_LM,
	SBI_EXT_RENESAS_RZFIVE_ETH_WORKAROUND,
};

static bool andes45_cache_controllable(void)
{
	return (((csr_read(CSR_MICM_CFG) & MICM_CFG_ISZ_MASK) ||
		 (csr_read(CSR_MDCM_CFG) & MDCM_CFG_DSZ_MASK)) &&
		(csr_read(CSR_MMSC_CFG) & MMSC_CFG_CCTLCSR_MASK) &&
		(csr_read(CSR_MCACHE_CTL) & MCACHE_CTL_CCTL_SUEN_MASK) &&
		misa_extension('U'));
}

static bool andes45_iocp_disabled(void)
{
	return (csr_read(CSR_MMSC_CFG) & MMSC_IOCP_MASK) ? false : true;
}

static bool andes45_apply_iocp_sw_workaround(void)
{
	return andes45_cache_controllable() & andes45_iocp_disabled();
}

int andes_sbi_vendor_ext_provider(long funcid,
				  const struct sbi_trap_regs *regs,
				  unsigned long *out_value,
				  struct sbi_trap_info *out_trap,
				  const struct fdt_match *match)
{
	switch (funcid) {
	case SBI_EXT_ANDES_IOCP_SW_WORKAROUND:
		*out_value = andes45_apply_iocp_sw_workaround();
		break;

	case SBI_EXT_RENESAS_RZFIVE_GET_MCACHE_CTL_STATUS:
		*out_value = csr_read(0x7ca);
		break;

	case SBI_EXT_RENESAS_RZFIVE_GET_MMISC_CTL_STATUS:
		*out_value = csr_read(0x7d0);
		break;

	case SBI_EXT_RENESAS_RZFIVE_READ_LM: {
		volatile char *base = (volatile char *)regs->a0;

		if (regs->a0 < 0x30000 || regs->a0 >= 0x50000) {
			*out_value = 0x0;
			return SBI_EINVAL;
		}
		*out_value = readq(base);
		break;
	}

	case SBI_EXT_RENESAS_RZFIVE_WRITE_LM: {
		volatile char *base = (volatile char *)regs->a0;
		u64 val = (u64)regs->a1;

		if (regs->a0 < 0x30000 || regs->a0 >= 0x50000) {
			*out_value = 0x0;
			return SBI_EINVAL;
		}
		writeq(val, base);
		*out_value = readq(base);
		break;
	}

	case SBI_EXT_RENESAS_RZFIVE_ETH_WORKAROUND: {
		uintptr_t mcache_ctl_val = csr_read(0x7ca);
		u8 status = (u8)regs->a0;

		if (status)
			mcache_ctl_val |= BIT(1);
		else
			mcache_ctl_val &= ~BIT(1);
		csr_write(0x7cc, 6);
		csr_write(0x7ca, mcache_ctl_val);
		if (status) {
			uint32_t *l2c_ctl_base = (void *)0x13400008;
			uint32_t l2c_ctl_val = *l2c_ctl_base;
			l2c_ctl_val |= 0x1;
			*l2c_ctl_base = l2c_ctl_val;
			l2c_ctl_val = *l2c_ctl_base;
			while ((l2c_ctl_val & BIT(14)))
				l2c_ctl_val = *l2c_ctl_base;
		}
		break;
	}

	default:
		return SBI_EINVAL;
	}

	return 0;
}
