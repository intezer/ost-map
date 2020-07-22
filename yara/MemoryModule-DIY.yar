rule MemoryModule {
	strings:
        // First block:
        // mov <reg>, 0x4D5A
        // cmp [reg], reg
		$s1 = {B? 4D 5A 00 00 66 39 }
        // Second block:
        // mov ecx, 0xC1
        // call cs:<mem>
        // xor eax, eax
		$s2 = {B9 C1 00 00 00 FF 15 ?? ?? ?? ?? 33 C0 }
	condition:
		$s1 and $s2 in (@s1..@s1+0x800)
}


