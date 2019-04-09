#include "../HyperPlatform/util.h"
#include "nest_svm_handler.h"
#include "../HyperPlatform/vmm.h"
#include "../kHypervisor/vmx_common.h"
#include "../HyperPlatform/asm.h"
#include "../HyperPlatform/common.h"

VOID SvmVmxonEmulate(_In_ GuestContext* guest_context) 
{
  VCPUVMX* nested_vmx = NULL;
  ULONG64 InstructionPointer = 0;
  ULONG64 StackPointer = 0;
  ULONG64 vmxon_region_pa = 0;
  ULONG64 guest_address = NULL;
  VmControlStructure* vmxon_region_struct = NULL;
  PROCESSOR_NUMBER number = {0};

  InstructionPointer = {UtilVmRead64(VmcsField::kGuestRip)};
  StackPointer = {UtilVmRead64(VmcsField::kGuestRsp)};   

//   if (VmmpGetvCpuMode(guest_context) == VmxMode) 
//   {
//     HYPERPLATFORM_LOG_DEBUG_SAFE(("Current vCPU already in VMX mode !"));
//     VMfailInvalid(VmmpGetFlagReg(guest_context));
//     return ;
//   } 

  nested_vmx = (VCPUVMX*)ExAllocatePool(NonPagedPoolNx, sizeof(VCPUVMX));

  nested_vmx->inRoot = RootMode;
  nested_vmx->blockINITsignal = TRUE;
  nested_vmx->blockAndDisableA20M = TRUE;
  nested_vmx->vmcs02_pa = 0xFFFFFFFFFFFFFFFF;
  nested_vmx->vmcs12_pa = 0xFFFFFFFFFFFFFFFF;
  nested_vmx->svmVmcbGuest12_pa = 0xFFFFFFFFFFFFFFFF;
  nested_vmx->svmVmcbHost12_pa = 0xFFFFFFFFFFFFFFFF;
  __vmx_vmptrst(&nested_vmx->vmcs01_pa);
  nested_vmx->vmxon_region = vmxon_region_pa;  // not uesd
  nested_vmx->InitialCpuNumber = KeGetCurrentProcessorNumberEx(&number);

  // vcpu etner vmx-root mode now
  VmmpEnterVmxMode(guest_context);
  VmmpSetvCpuVmx(guest_context, nested_vmx);

  HYPERPLATFORM_LOG_DEBUG(
      "VMXON: Guest Instruction Pointer %I64X Guest Stack Pointer: %I64X  "
      "Guest VMXON_Region: %I64X stored at %I64x physical address\r\n",
      InstructionPointer, StackPointer, vmxon_region_pa, guest_address);

  HYPERPLATFORM_LOG_DEBUG(
      "VMXON: Run Successfully with VMXON_Region:  %I64X Total Vitrualized "
      "Core: %x  Current Cpu: %x in Cpu Group : %x  Number: %x \r\n",
      vmxon_region_pa, nested_vmx->InitialCpuNumber, number.Group,
      number.Number);

}

VOID SvmVmsaveEmulate(_In_ GuestContext* guest_context) 
{
    do 
    {
        if (GetGuestCPL() != 0)
        {
            ThrowGerneralFaultInterrupt(); // #GP
            break;
        }

        VCPUVMX* NestedvCPU = VmmpGetVcpuVmx(guest_context);
        if (NULL == NestedvCPU)
        {
             SvmVmxonEmulate(guest_context);
             if (VmmpGetvCpuMode(guest_context) != VmxMode) 
             {
                    HYPERPLATFORM_LOG_DEBUG_SAFE(("VMCLEAR: Current vCPU already in VMX mode ! \r\n"));
                    ThrowGerneralFaultInterrupt();  // #GP
                    break;
             }
             if (VmxGetVmxMode(VmmpGetVcpuVmx(guest_context)) != RootMode) 
             {
               // Inject ...'
               HYPERPLATFORM_LOG_DEBUG_SAFE(("VMCLEAR : Unimplemented third level virualization \r\n"));
               ThrowGerneralFaultInterrupt();  // #GP
               break;
             }
             // clear
             NestedvCPU = VmmpGetVcpuVmx(guest_context);
             if (!NestedvCPU)
             {
               ThrowGerneralFaultInterrupt();  // #GP
               break;
             }
             __vmx_vmclear(&NestedvCPU->vmcs02_pa);
        }    

        ULONG64 guest_pa_address = 0;
        ULONG64 guest_va_adress = 0;
        const auto register_used = VmmpSelectRegister(0, guest_context); // rax
        guest_pa_address = *register_used;
        guest_va_adress = (ULONG64)UtilVaFromPa(guest_pa_address);

//         Store to a VMCB at system - physical address rAX : FS, GS, TR,
//             LDTR(including all hidden state) KernelGsBase STAR, LSTAR, CSTAR,
//             SFMASK SYSENTER_CS, SYSENTER_ESP,
//             SYSENTER_EIP
        Gdtr gdtr = {};
        __sgdt(&gdtr);
        VMCB * SvmGuestVmcb = (VMCB *)guest_va_adress;
        SvmGuestVmcb->StateSaveArea.FsSelector = UtilVmRead(VmcsField::kGuestFsSelector);
        SvmGuestVmcb->StateSaveArea.FsAttrib = UtilVmRead(VmcsField::kGuestFsArBytes);
        SvmGuestVmcb->StateSaveArea.FsLimit = UtilVmRead(VmcsField::kGuestFsLimit);
        SvmGuestVmcb->StateSaveArea.FsBase = UtilVmRead64(VmcsField::kGuestFsBase);

        SvmGuestVmcb->StateSaveArea.GsSelector = UtilVmRead(VmcsField::kGuestGsSelector);
        SvmGuestVmcb->StateSaveArea.GsAttrib = UtilVmRead(VmcsField::kGuestGsArBytes);
        SvmGuestVmcb->StateSaveArea.GsLimit = UtilVmRead(VmcsField::kGuestGsLimit);
        SvmGuestVmcb->StateSaveArea.GsBase = UtilVmRead64(VmcsField::kGuestGsBase);

        SvmGuestVmcb->StateSaveArea.TrSelector = UtilVmRead(VmcsField::kGuestTrSelector);
        SvmGuestVmcb->StateSaveArea.TrAttrib = UtilVmRead(VmcsField::kGuestTrArBytes);
        SvmGuestVmcb->StateSaveArea.TrLimit = UtilVmRead(VmcsField::kGuestTrLimit);
        SvmGuestVmcb->StateSaveArea.TrBase = UtilVmRead64(VmcsField::kGuestTrBase);

        SvmGuestVmcb->StateSaveArea.LdtrSelector = UtilVmRead(VmcsField::kGuestLdtrSelector);
        SvmGuestVmcb->StateSaveArea.LdtrAttrib = UtilVmRead(VmcsField::kGuestLdtrArBytes);
        SvmGuestVmcb->StateSaveArea.LdtrLimit = UtilVmRead(VmcsField::kGuestLdtrLimit);
        SvmGuestVmcb->StateSaveArea.LdtrBase = UtilVmRead64(VmcsField::kGuestLdtrBase);

        SvmGuestVmcb->StateSaveArea.KernelGsBase = UtilReadMsr(Msr::kIa32KernelGsBase);
        SvmGuestVmcb->StateSaveArea.Star = UtilReadMsr(Msr::kIa32Star);
        SvmGuestVmcb->StateSaveArea.LStar = UtilReadMsr(Msr::kIa32Lstar);
        SvmGuestVmcb->StateSaveArea.SysenterCs = UtilVmRead64(VmcsField::kGuestSysenterCs);
        SvmGuestVmcb->StateSaveArea.SysenterEsp = UtilVmRead64(VmcsField::kGuestSysenterEsp);
        SvmGuestVmcb->StateSaveArea.SysenterEip = UtilVmRead64(VmcsField::kGuestSysenterEip);

    } while (FALSE);

}

VOID SvmVmloadEmulate(_In_ GuestContext* guest_context) 
{
    do 
    {
        if (VmmpGetvCpuMode(guest_context) != VmxMode)
		{
            HYPERPLATFORM_LOG_DEBUG_SAFE(("Current vCPU already in VMX mode ! \r\n"));
            ThrowGerneralFaultInterrupt();  // #GP
			break;
		}

        	// if VCPU not run in VMX mode 
		if (VmxGetVmxMode(VmmpGetVcpuVmx(guest_context)) != RootMode)
		{
			// Inject ...'
			HYPERPLATFORM_LOG_DEBUG_SAFE("VMPTRLD Unimplemented third level virualization %I64x \r\n", VmmpGetVcpuVmx(guest_context));
		    ThrowGerneralFaultInterrupt();  // #GP
			break;
		}

        VCPUVMX* nested_vmx = NULL;
        PUCHAR      vmcs02_region_va = NULL;
        ULONG64    vmcs02_region_pa = NULL; 
        ULONG64 guest_pa_address = 0;
        ULONG64 guest_va_adress = 0;
        const auto register_used = VmmpSelectRegister(0, guest_context);  // rax
        guest_pa_address = *register_used;
        guest_va_adress = (ULONG64)UtilVaFromPa(guest_pa_address);

        VMCB* SvmGuestVmcb = (VMCB*)guest_va_adress;

        //if is it not page aglined
        if (!CheckPageAlgined(guest_pa_address))
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMPTRLD: not page aligned physical address %I64X ! \r\n"),
            guest_pa_address);
			ThrowGerneralFaultInterrupt();  // #GP
			break;
		}

        vmcs02_region_va = (PUCHAR)ExAllocatePool(NonPagedPoolNx, PAGE_SIZE); 
		if (!vmcs02_region_va)
		{
            HYPERPLATFORM_LOG_DEBUG_SAFE(("VMPTRLD: vmcs02_region_va NULL ! \r\n"));
			ThrowGerneralFaultInterrupt();  // #GP
			break;
		}

        nested_vmx = VmmpGetVcpuVmx(guest_context);

        RtlZeroMemory(vmcs02_region_va, PAGE_SIZE); 
        vmcs02_region_pa = UtilPaFromVa(vmcs02_region_va); 
        nested_vmx->vmcs02_pa = vmcs02_region_pa;		    //vmcs02' physical address - DIRECT VMREAD/WRITE
        nested_vmx->kVirtualProcessorId = (USHORT)KeGetCurrentProcessorNumberEx(nullptr) + 1;

        HYPERPLATFORM_LOG_DEBUG_SAFE("[VMPTRLD] Run Successfully \r\n");
        HYPERPLATFORM_LOG_DEBUG_SAFE("[VMPTRLD] VMCS02 PA: %I64X VA: %I64X  \r\n", vmcs02_region_pa, vmcs02_region_va);
        HYPERPLATFORM_LOG_DEBUG_SAFE("[VMPTRLD] Current Cpu: %x \r\n", nested_vmx->InitialCpuNumber);

//         Load from a VMCB at system - physical address rAX : FS, GS, TR,
//         LDTR(including all hidden state) KernelGsBase STAR, LSTAR, CSTAR,
//         SFMASK SYSENTER_CS, SYSENTER_ESP, SYSENTER_EIP
//         put into vmrun
    } while (FALSE);
}

VOID SvmVmrunEmulate(_In_ GuestContext* guest_context) 
{
    do 
    {
        HYPERPLATFORM_COMMON_DBG_BREAK();
        VCPUVMX* NestedvCPU = VmmpGetVcpuVmx(guest_context);
        HYPERPLATFORM_LOG_DEBUG_SAFE("-----start vmrun---- \r\n");

        if (GetGuestCPL() != 0)
        {
            ThrowGerneralFaultInterrupt(); // #GP
            break;
        }

        if (!NestedvCPU)
		{
            ThrowGerneralFaultInterrupt();  // #GP
			break;
		}

        // if VCPU not run in VMX mode 
		if (VmxGetVmxMode(VmmpGetVcpuVmx(guest_context)) != RootMode)
		{
			// Inject ...'
			HYPERPLATFORM_LOG_DEBUG(" Vmlaunch: Unimplemented third level virualization VMX: %I64x  VMCS12: %I64x \r\n", VmmpGetVcpuVmx(guest_context), NestedvCPU->vmcs12_pa);
			ThrowGerneralFaultInterrupt();  // #GP
			break;
		}

    } while (FALSE);
}