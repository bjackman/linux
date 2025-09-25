.. SPDX-License-Identifier: GPL-2.0

=============================
Address Space Isolation (ASI)
=============================

.. Warning::
   ASI is incomplete. It is available to enable for testing but doesn't offer
   security guarantees. See the "Status" section for details.

Introduction
============

ASI is a mechanism to mitigate a broad class of CPU vulnerabilities. While the
precise scope of these vulnerabilities is complex, ASI, when appropriately
configured, mitigates most well-known CPU exploits.

This class of vulnerabilities could be mitigated by the following *blanket
mitigation*:

1. Remove all potentially secret data from the attacker's address space (i.e.
   enable PTI).

2. Disable SMT.

3. Whenever transitioning from an untrusted domain (i.e. a userspace process or
   a KVM guest) into a potential victim domain (in this case, the kernel), clear
   all state from the branch predictor.

4. Whenever transitioning from the victim domain into an untrusted domain, clear
   all microarchitectural state that might be exploited to leak data from a
   sidechannel (e.g. L1D$, load and store buffers, etc).

The performance overhead of this mitigation is unacceptable for most use-cases. In the
abstract, ASI works by doing these things, but only *selectively*.

What ASI does
=============

Memory is divided into *restricted* and *nonsensitive* memory. Sensitive memory
refers to memory that might contain data the kernel is obliged to protect from
an attacker. Specifically, this includes any memory that might contain user data
or could be indirectly used to steal user data (such as keys). All other memory
is nonsensitive.

A new address space, called the *nonsensitive address space*, is introduced, where
sensitive memory is not mapped. The "normal" address space where everything is
mapped (equivalent to the address space used by the kernel when ASI is disabled)
is called the *sensitive address space*. When the CPU enters the kernel, it
does so in the nonsensitive address space (no sensitive memory mapped).

If the kernel accesses sensitive memory, it triggers a page fault. In this page
fault handler, the kernel transitions from the nonsensitive to the sensitive
address space. At this point, a security boundary is crossed: just before the
transition, the kernel flushes branch predictor state as it would in point
3 of the blanket mitigation above. Furthermore, SMT is disabled (the sibling
hyperthread is paused).

.. Note::
  Because the nonsensitive -> sensitive transition is triggered by a page
  fault, it is totally automatic and transparent to the rest of the kernel.
  Kernel code is not generally aware of memory sensitivity.

Before returning to the untrusted domain, the kernel transitions back to the
nonsensitive address space. Immediately afterwards, it flushes any potential
side-channels, like in step 4 of the blanket mitigation above. At this point SMT
is also re-enabled.

Why it works
============

In terms of security, this is equivalent to the blanket mitigation. However,
instead of doing these expensive things on every transition into and out of the
kernel, ASI does them only on transitions between its address spaces. Most
entries to the kernel do not require access to any sensitive data. This means
that a roundtrip can be performed without doing any of the flushes mentioned
above.

This selectivity means that much more aggressive mitigation techniques are
available for a dramatically reduced performance cost. In turn, these more
aggressive techniques tend to be more generic. For example, instead of needing
to develop new microarchitecture-specific techniques to efficiently eliminate
attacker "mistraining", ASI makes it viable to just use generic flush operations
like IBPB.

Status
======

ASI is currently still in active development. None of the features described
above actually work yet.

Prototypes only exist for ASI on x86 and in its initial development it will
remain x86-specific. This is not fundamental to its design, it could eventually
be extended for other architectures too as needed.

Resources
=========

* Presentation at LSF/MM/BPF 2024, introducing ASI: https://www.youtube.com/watch?v=DxaN6X_fdlI

* RFCs on LKML:
  * `Junaid Shahid, 2022 <https://lore.kernel.org/all/20220223052223.1202152-1-junaids@google.com/>`__
  * `Brendan Jackman, 2025 <https://lore.kernel.org/linux-mm/20250110-asi-rfc-v2-v2-0-8419288bc805@google.com>`__
