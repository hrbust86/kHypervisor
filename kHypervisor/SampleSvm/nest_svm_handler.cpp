#include "../HyperPlatform/util.h"
#include "nest_svm_handler.h"
#include "../HyperPlatform/vmm.h"
#include "../kHypervisor/vmx_common.h"

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



    } while (FALSE);

}