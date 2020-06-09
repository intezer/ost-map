private rule id_1
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 48 [4] 48 [4] 48 [4] 48 [4] 41 [1] 41 [1] 41 [1] 48 [3] 48 [3] 48 [2] B9 [4] 66 [4] 0F 85 [4] 8B [6] 48 [2] E8 [4] 44 [2] 48 [2] 4C [2] 41 [3] E8 [4] 41 [3] 48 [2] 8B [1] 48 [2] E8 [4] 41 [3] 44 [2] 4C [2] 85 [1] 0F 84 [4] 45 [2] 0F 1F }

	condition:
		any of them
}

private rule id_2
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 48 [4] 48 [4] 48 [4] 48 [2] 4C [4] 4C [4] E8 [4] 48 [2] 44 [2] 4C [2] 41 [3] E8 [4] 41 [3] 48 [2] 8B [1] 48 [2] E8 [4] 41 [3] 8B [1] 48 [2] 85 [1] 0F 84 [4] 45 [2] 0F 1F [1] 48 [3] 44 [2] FF C? 48 [2] 0F B7 [2] 44 [4] 4C [3] 72 [1] 44 [4] 41 [3] 45 [2] 7E }

	condition:
		any of them
}

private rule id_3
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [2] 8B [2] 03 [2] 89 [2] 8B [2] 83 [2] 89 [2] 8B [2] 8B [2] 03 [1] 89 [2] 8B [2] 8B [2] 03 [2] 89 [2] 8B [2] 8B [2] 03 [2] 89 [2] B8 [4] 66 [3] 0F B7 [2] 85 [1] 0F 8E }
		$b0 = { 8B [2] 8B [2] 03 [2] 89 [2] 6A [1] 68 [4] 8B [2] 8B [2] 5? 6A [1] FF 5? [1] 89 [2] 8B [2] 8B [2] 89 [2] 8B [2] 89 [2] 8B [2] 89 [2] 8B [2] 8B [2] 8B [2] F3 [1] 8B [2] 0F B7 [2] 8B [2] 8D [3] 89 }

	condition:
		any of ($a*) and any of ($b*)
}

private rule id_4
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 48 [3] 33 [1] 41 [5] 48 [2] 44 [3] 8B [2] 41 [2] 8B [2] 48 [2] 48 [2] 45 [2] 4C [2] F3 [1] 0F B7 [2] BA [4] 66 [4] 74 }
		$b0 = { 66 [3] 8B [5] 49 [2] 8B [2] 41 [2] 0F 84 [4] 8B [1] 49 [2] 41 [2] 8B [1] 8B [2] 49 [2] 49 [2] 4C [2] 45 [2] EB }

	condition:
		any of ($a*) and any of ($b*)
}

private rule id_5
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [2] 03 [1] 89 [2] 8D [2] 89 [2] 8B [1] 85 [1] 0F 85 [4] 8B [2] 8B [2] 8B [2] 6A [1] 6A [1] 6A [1] 03 [1] FF 5? [1] FF 7? [1] 6A [1] FF 7? [1] FF D? 5? 8B [1] 5? 5? 8B [1] 5? C2 }

	condition:
		any of them
}

private rule id_6
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 4D [2] 4D [2] 75 [1] 8B [2] 48 [2] 8B [2] 85 [1] 0F 85 [4] 8B [2] 45 [2] 33 [1] 48 [3] 48 [2] FF 5? [2] 4C [7] BA [4] 48 [2] FF D? 48 [2] 48 [3] 41 [1] 41 [1] 41 [1] 41 [1] 5? 5? 5? 5? C3 }

	condition:
		any of them
}

private rule id_7
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 40 [1] 48 [3] 48 [3] 48 [2] 0F B7 [3] B9 [4] 66 [2] 75 }
		$b0 = { B9 [4] 66 [2] 75 [1] 8B [6] 48 [4] 48 [4] 48 [4] 48 [2] 4C [4] 4C [4] E8 [4] 48 [2] 44 [2] 4C [2] 41 [3] E8 [4] 41 [3] 48 [2] 8B [1] 48 [2] E8 [4] 41 [3] 8B [1] 48 [2] 85 [1] 0F 84 }

	condition:
		any of ($a*) and any of ($b*)
}

private rule id_8
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [2] 0F B7 [2] 8B [2] 66 [3] 66 [3] 8B [2] 66 [3] 85 [1] 74 }
		$b0 = { 8B [2] 05 [4] 89 [2] 8B [2] 8B [2] 03 [1] 89 [2] 8B [2] 83 [3] 0F 84 }

	condition:
		any of ($a*) and any of ($b*)
}

private rule id_9
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 48 [3] 33 [1] 41 [5] 48 [2] 44 [3] 8B [2] 41 [2] 8B [2] 48 [2] 48 [2] 45 [2] 4C [2] F3 [1] 0F B7 [2] BA [4] 66 [4] 74 [1] 48 [4] 66 [3] 8B [1] 8B [2] 8B [2] 48 [2] 49 [2] F3 [1] 48 [3] 66 [4] 75 }

	condition:
		any of them
}

private rule id_10
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 49 [3] 41 [5] BF [4] 48 [3] 45 [3] 8B [6] 44 [4] 44 [4] 4C [2] 4C [2] 41 [2] 44 [2] 48 [2] 8A [1] 41 [3] 0F BE [1] 49 [2] 44 [2] 8A [1] 84 [1] 75 }

	condition:
		any of them
}

private rule id_11
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [6] 48 [4] 48 [4] 48 [4] 48 [2] 4C [4] 4C [4] E8 [4] 48 [2] 44 [2] 4C [2] 41 [3] E8 [4] 41 [3] 48 [2] 8B [1] 48 [2] E8 [4] 41 [3] 8B [1] 48 [2] 85 [1] 0F 84 [4] 45 [2] 0F 1F [1] 48 [3] 44 [2] FF C? 48 [2] 0F B7 [2] 44 [4] 4C [3] 72 }

	condition:
		any of them
}

private rule id_12
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 0F B7 [2] 85 [1] 0F 8E }
		$b0 = { 8B [2] 8B [2] 03 [2] 89 [2] 6A [1] 68 [4] 8B [2] 8B [2] 5? 6A [1] FF 5? [1] 89 [2] 8B [2] 8B [2] 89 [2] 8B [2] 89 [2] 8B [2] 89 [2] 8B [2] 8B [2] 8B [2] F3 [1] 8B [2] 0F B7 [2] 8B [2] 8D [3] 89 [2] 8B [2] 0F B7 [2] 8B [2] 66 [3] 66 [3] 8B [2] 66 [3] 85 [1] 74 }

	condition:
		any of ($a*) and any of ($b*)
}

private rule id_13
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 81 F? [4] 0F 85 [4] 49 [3] 41 [5] BF [4] 48 [3] 45 [3] 8B [6] 44 [4] 44 [4] 4C [2] 4C [2] 41 [2] 44 [2] 48 [2] 8A }

	condition:
		any of them
}

private rule id_14
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [2] 8B [2] 03 [2] 89 [2] 6A [1] 68 [4] 8B [2] 8B [2] 5? 6A [1] FF 5? [1] 89 [2] 8B [2] 8B [2] 89 [2] 8B [2] 89 [2] 8B [2] 89 [2] 8B [2] 8B [2] 8B [2] F3 [1] 8B [2] 0F B7 [2] 8B [2] 8D [3] 89 [2] 8B [2] 0F B7 [2] 8B [2] 66 [3] 66 [3] 8B [2] 66 [3] 85 [1] 74 [1] 8B [2] 8B [2] 03 [2] 89 [2] 8B [2] 8B [2] 03 [2] 89 [2] 8B [2] 8B [2] 89 [2] 8B [2] 8B [2] 8B [2] F3 [1] 8B [2] 83 [2] 89 [2] EB }

	condition:
		any of them
}

private rule id_15
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 48 [2] 48 [2] 66 [3] 75 [1] 81 F? [4] 0F 85 [4] 49 [3] BF [4] 48 [3] 8B [6] B8 [4] 44 [4] 8B [3] 0F B7 [1] 4C [2] 48 [2] 45 [2] 44 }

	condition:
		any of them
}

private rule id_16
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 81 F? [4] 0F 85 [4] 49 [3] BF [4] 48 [3] 8B [6] B8 [4] 44 [4] 8B [3] 0F B7 [1] 4C [2] 48 [2] 45 [2] 44 [3] 45 [2] 41 [2] 4C [2] 41 }

	condition:
		any of them
}

private rule id_17
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 49 [3] BF [4] 48 [3] 8B [6] B8 [4] 44 [4] 8B [3] 0F B7 [1] 4C [2] 48 [2] 45 [2] 44 [3] 45 [2] 41 [2] 4C [2] 41 [2] C1 [2] 0F BE [1] 49 [2] 03 [1] 41 [2] 84 [1] 75 }

	condition:
		any of them
}

rule ReflectiveDLLInjection
{
	meta:
		author = "Paul"
		date = "June 2020"
	condition:
		(id_1 or id_2 or id_3 or id_4 or id_5 or id_6 or id_7 or id_8 or id_9 or id_10 or id_11 or id_12 or id_13 or id_14 or id_15 or id_16 or id_17)
}