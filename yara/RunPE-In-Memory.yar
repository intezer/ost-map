private rule id_1
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 6A [1] 68 [4] 6A [1] 6A [1] FF 1? [4] 8B [1] 5? 89 [2] C7 [5] FF 7? [1] FF 1? [4] 85 [1] 0F 84 [4] 6A [1] 68 [4] FF 7? [1] FF 7? [1] FF 7? [1] FF 1? [4] 6A [1] 89 [2] FF 7? [1] 5? 5? FF 7? [1] FF 1? [4] 33 [1] 33 [1] 66 [3] 73 [1] 8D }
		$a1 = { 6A [1] 68 [4] 6A [1] 6A [1] FF 1? [4] 8B [1] C7 [5] 8B [2] 5? 5? 89 [2] FF 1? [4] 85 [1] 0F 84 [4] 8B [2] 8B [2] 8B [2] 6A [1] 68 [4] 5? 5? 5? FF 1? [4] 8B [2] 6A [1] 89 [2] 8B [2] 5? 5? 5? 5? FF 1? [4] 33 [1] 33 [1] 66 [3] 73 [1] 8D }

	condition:
		any of them
}

private rule id_2
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 03 [1] 5? 68 [4] E8 [4] 8B [2] 4? 2B [2] 83 [2] 01 [1] 83 [2] 8B [2] 3B [2] 72 [1] 8B [2] 8B [2] 8B [2] 03 [2] 89 [2] 3B [2] 0F 82 }

	condition:
		any of them
}

private rule id_3
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 48 [4] 5? 41 [1] 41 [1] 48 [3] 48 [6] 4C [2] FF 1? [4] 33 [1] 48 [2] 48 [2] 44 [3] FF 1? [4] 48 [2] FF 1? [4] 48 [2] 48 [2] FF 1? [4] 48 [3] FF 1? [4] 4C [2] 41 [5] 48 [2] 48 [2] 4C [2] FF 1? [4] 48 [2] FF 1? [4] 4D [2] 0F 84 [4] B8 [4] 66 [3] 0F 85 [4] 49 [3] 3D [4] 0F 8F }
		$a1 = { 48 [4] 5? 41 [1] 41 [1] 48 [3] 48 [6] 4C [2] FF 1? [4] 33 [1] 44 [3] 48 [2] 48 [2] FF 1? [4] 48 [2] FF 1? [4] 48 [2] 48 [2] FF 1? [4] 48 [3] FF 1? [4] 4C [2] 41 [5] 48 [2] 48 [2] 4C [2] FF 1? [4] 48 [2] FF 1? [4] 4D [2] 0F 84 [4] B8 [4] 66 [3] 0F 85 [4] 49 [3] 3D [4] 0F 8F }
		$a2 = { 48 [4] 5? 5? 5? 5? 41 [1] 41 [1] 48 [3] 48 [6] 48 [2] FF 1? [4] 33 [1] 48 [2] 48 [2] 44 [3] FF 1? [4] 48 [2] FF 1? [4] 48 [2] 48 [2] FF 1? [4] 48 [3] FF 1? [4] 4C [2] 41 [5] 48 [2] 48 [2] 48 [2] FF 1? [4] 48 [2] FF 1? [4] 48 [2] 0F 84 [4] 41 [5] 66 [4] 0F 85 [4] 48 [3] 3D [4] 0F 8F }

	condition:
		any of them
}

private rule id_4
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 6A [1] 68 [4] FF 7? [1] FF 7? [1] FF 7? [2] FF 1? [4] 6A [1] 89 [3] FF 7? [1] 5? 5? FF 7? [2] FF 1? [4] 33 [1] C7 [7] 66 [3] 73 [1] 8D [5] 0F 1F [3] 8B [1] 03 [3] 6A [1] FF 7? [1] 5? 8B [2] 03 [3] 5? FF 7? [2] FF 1? [4] 8B [3] 8D [2] 0F B7 [2] 4? 89 [3] 3B [1] 7C }

	condition:
		any of them
}

private rule id_5
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [2] 8D [2] 5? 68 [4] E8 [4] 8B [2] 2B [2] 8B [2] 01 [1] 4? 83 [2] 83 [2] 3B [2] 72 [1] 8B [2] 8B [2] 03 [1] 89 [2] 3B [2] 0F 82 }

	condition:
		any of them
}

private rule id_6
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8D [2] 5? 68 [4] E8 [4] FF 7? [1] 8B [1] 03 [1] 5? 8B [2] 03 [1] 5? E8 [4] 8B [3] 8D [2] 8B [3] 83 [2] 4? 89 [3] 0F B7 [2] 3B [1] 72 [1] 68 [4] E8 [4] 83 [2] B9 [4] 85 [1] 0F 84 [4] 66 [2] 0F 85 }
		$a1 = { 8D [2] 5? 68 [4] E8 [4] FF 7? [1] 8B [1] 03 [1] 5? 8B [2] 03 [1] 5? E8 [4] 8B [3] 8D [2] 8B [3] 83 [2] 4? 89 [3] 0F B7 [2] 3B [1] 7C [1] 68 [4] E8 [4] 83 [2] B9 [4] 85 [1] 0F 84 [4] 66 [2] 0F 85 }

	condition:
		any of them
}

private rule id_7
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 6A [1] 68 [4] FF 7? [1] FF 7? [1] FF 7? [1] FF 1? [4] 6A [1] 89 [2] FF 7? [1] 5? 5? FF 7? [1] FF 1? [4] 33 [1] 33 [1] 66 [3] 73 [1] 8D [5] 8B [1] 03 [2] 6A [1] FF 7? [1] 5? 8B [2] 03 [2] 5? FF 7? [1] FF 1? [4] 0F B7 [2] 8D [2] 4? 3B [1] 7C }

	condition:
		any of them
}

private rule id_8
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8D [2] 5? 68 [4] E8 [4] FF 7? [1] 8B [1] 03 [1] 5? 8B [2] 03 [1] 5? E8 [4] 8B [3] 8D [2] 8B [3] 83 [2] 4? 89 [3] 0F B7 [3] 3B [1] 72 [1] 8B [3] 8B [1] E8 [4] 8B [3] 3B [1] 74 }
		$a1 = { 8D [2] 5? 68 [4] E8 [4] FF 7? [1] 8B [1] 03 [1] 5? 8B [2] 03 [1] 5? E8 [4] 8B [3] 8D [2] 8B [3] 83 [2] 4? 89 [3] 0F B7 [3] 3B [1] 7C [1] 8B [3] 8B [1] E8 [4] 8B [3] 3B [1] 74 }

	condition:
		any of them
}

private rule id_9
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 48 [6] FF 1? [4] 44 [3] 49 [2] 48 [2] 48 [3] E8 [4] 66 [3] 73 [1] 48 [6] 0F 1F [2] 0F 1F [6] 48 [2] 48 [7] 48 [2] 48 [3] 48 [6] E8 [4] 8B [1] 8B [2] 49 [2] 44 [3] 48 [2] E8 [4] 0F B7 [2] 48 [3] FF C? 3B [1] 7C }
		$a1 = { 48 [6] FF 1? [4] 44 [3] 49 [2] 48 [2] 48 [3] E8 [4] 66 [3] 73 [1] 48 [6] 0F 1F [6] 48 [2] 48 [7] 48 [2] 48 [3] 48 [6] FF 1? [4] 8B [1] 8B [2] 44 [3] 49 [2] 48 [2] E8 [4] 0F B7 [2] FF C? 48 [3] 3B [1] 7C }

	condition:
		any of them
}

private rule id_10
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8D [5] E8 [4] 8B [2] 99 03 [1] 13 [2] 5? 5? 5? 8B [1] 5? E8 [4] 8D [5] E8 [4] 85 [1] 75 [1] 8B [5] 8B [2] 8B [6] 8D [6] 83 [2] 83 [3] 75 [1] 83 }

	condition:
		any of them
}

private rule id_11
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 83 [3] 8A [2] 88 [2] 75 [1] 8B [2] 8B [1] 6A [1] 83 [2] 5? E8 [4] 8D [2] 89 [2] 8B [1] 8B [2] C7 [6] 8B [1] 8B [2] 8D [2] 89 [3] 8B [1] 8B [2] C7 [6] 8B [1] 8B [2] 8D [2] 89 [3] C7 [6] 8B [1] 6A [1] 8B [2] C7 [6] 8B [1] 8B [2] 8D [2] 89 [3] 8D [2] 89 [2] C7 [5] E8 [4] 8B [1] 0F 57 [1] 83 [2] 66 [3] 6A [1] C6 [3] E8 [4] 89 [2] 83 [2] 8D [2] 8D [2] 89 [2] 89 [2] 8D [2] 8B [2] 8D [2] 89 [2] 8D [2] 8B [2] 8D [2] 83 [2] C7 [5] C6 [3] C6 [3] 8B [2] 89 [2] 8B [2] 8B [2] 89 [2] 89 [2] 89 [2] 89 [2] 89 [2] 8B [2] C7 [5] C7 [5] C7 [5] A1 [4] C7 [5] 8B [2] C7 [5] C7 [5] 89 [2] A1 [4] C7 [6] 89 [2] C7 [6] C6 [3] 6A [1] 6A [1] FF 7? [1] E8 [4] 83 [2] 85 [1] 74 }

	condition:
		any of them
}

private rule id_12
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8D [2] 5? 68 [4] E8 [4] 8B [2] 8B [1] 8B [2] 5? 03 [1] 5? 03 [1] 5? E8 [4] 8B [3] 8B [3] 0F B7 [3] 4? 83 [2] 83 [2] 89 [3] 3B [1] 7C [1] 8B [1] 5? E8 [4] 8B [3] 83 [2] 3B [1] 74 }
		$a1 = { 8D [2] 5? 68 [4] E8 [4] 8B [2] 8B [1] 8B [2] 5? 03 [1] 5? 03 [1] 5? E8 [4] 8B [3] 8B [3] 0F B7 [3] 4? 83 [2] 83 [2] 89 [3] 3B [1] 72 [1] 8B [1] 5? E8 [4] 8B [3] 83 [2] 3B [1] 74 }

	condition:
		any of them
}

private rule id_13
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 68 [4] E8 [4] 83 [2] 89 [2] FF 7? [1] 5? 5? E8 [4] 33 [1] C7 [7] 83 [2] 66 [3] 73 [1] 81 C? [4] 8D [2] 5? 68 [4] E8 [4] FF 7? [1] 8B [1] 03 [1] 5? 8B [2] 03 [1] 5? E8 [4] 8B [3] 8D [2] 8B [3] 83 [2] 4? 89 [3] 0F B7 [2] 3B [1] 72 }
		$a1 = { 68 [4] E8 [4] 83 [2] 89 [2] FF 7? [1] 5? 5? E8 [4] 33 [1] C7 [7] 83 [2] 66 [3] 73 [1] 81 C? [4] 8D [2] 5? 68 [4] E8 [4] FF 7? [1] 8B [1] 03 [1] 5? 8B [2] 03 [1] 5? E8 [4] 8B [3] 8D [2] 8B [3] 83 [2] 4? 89 [3] 0F B7 [2] 3B [1] 7C }

	condition:
		any of them
}

private rule id_14
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 48 [3] 3D [4] 0F 8F [4] 81 3? [5] 4C [3] 4C [4] 0F 85 [4] 48 [6] 4C [4] 4D [3] 48 [6] 33 [1] 4C [7] 48 [2] 49 [2] 39 [1] 48 [3] E8 [4] 48 [6] FF 1? [4] 48 [2] 48 [6] FF 1? [4] 49 [3] 48 [6] FF D? 41 [3] 41 [5] 41 [5] 49 [2] FF 1? [4] 48 [2] 48 [2] 75 }

	condition:
		any of them
}

private rule id_15
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [1] 03 [2] 6A [1] FF 7? [1] 5? 8B [2] 03 [2] 5? FF 7? [1] FF 1? [4] 0F B7 [2] 8D [2] 4? 3B [1] 7C [1] 8B [2] 6A [1] 6A [1] 8D [2] 5? 8B [5] 83 [2] 5? FF 7? [1] FF 1? [4] 8B [2] 03 [2] 5? 89 [5] FF 7? [1] FF 1? [4] FF 7? [1] FF 1? }

	condition:
		any of them
}

private rule id_16
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 81 C? [4] 03 [1] 0F 1F [5] 8D [2] 5? 68 [4] E8 [4] FF 7? [1] 8B [1] 03 [1] 5? 8B [2] 03 [1] 5? E8 [4] 8B [3] 8D [2] 8B [3] 83 [2] 4? 89 [3] 0F B7 [3] 3B [1] 72 [1] 8B }
		$a1 = { 81 C? [4] 03 [1] 0F 1F [6] 8D [2] 5? 68 [4] E8 [4] FF 7? [1] 8B [1] 03 [1] 5? 8B [2] 03 [1] 5? E8 [4] 8B [3] 8D [2] 8B [3] 83 [2] 4? 89 [3] 0F B7 [3] 3B [1] 7C [1] 8B }

	condition:
		any of them
}

private rule id_17
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 44 [3] 48 [6] 4D [2] 49 [2] E8 [4] 8B [2] 8B [2] 48 [2] 0F 44 [1] 4A [3] 48 [2] 4E [3] 66 [1] 8B [2] 42 [3] 48 [2] 74 [1] 0F B7 [1] 49 [2] FF 1? [4] 48 [2] 8B [1] FF 1? [4] 48 [2] 48 [6] 4C [2] 48 [2] E8 [4] 49 [3] BF }
		$a1 = { 44 [3] 48 [6] 4D [2] 49 [2] FF 1? [4] 8B [2] 8B [2] 48 [2] 0F 44 [1] 4A [3] 48 [2] 4E [3] 8B [2] 42 [3] 48 [2] 74 [1] 0F B7 [1] 49 [2] FF 1? [4] 8B [1] 48 [2] FF 1? [4] 48 [2] 48 [6] 4C [2] 48 [2] FF 1? [4] 49 [3] BF }

	condition:
		any of them
}

private rule id_18
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [2] 8B [2] 8B [2] 6A [1] 68 [4] 5? 5? 5? FF 1? [4] 8B [2] 6A [1] 89 [2] 8B [2] 5? 5? 5? 5? FF 1? [4] 33 [1] 33 [1] 66 [3] 73 [1] 8D [5] 8B [2] 8B [1] 03 [2] 8B [2] 03 [2] 6A [1] 5? 8B [2] 5? 5? 5? FF 1? [4] 0F B7 [2] 4? 83 [2] 3B [1] 7C }

	condition:
		any of them
}

private rule id_19
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8D [6] E8 [4] 8B [1] 89 [3] 8B [2] 03 [1] 81 3? [4] 0F 85 [4] 6A [1] 8D [3] 0F 57 [1] 6A [1] 5? 0F 29 [3] E8 [4] 83 [2] 8D [3] 5? 8D [3] 5? 6A [1] 6A [1] 6A [1] 6A [1] 6A [1] 6A [1] 6A [1] 68 [4] FF 1? [4] 85 [1] 0F 84 [4] 6A [1] 68 [4] 6A [1] 6A [1] FF 1? [4] 5? 89 [3] C7 [5] FF 7? [2] FF 1? [4] 85 [1] 0F 84 }

	condition:
		any of them
}

private rule id_20
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 5? 8B [1] 83 [2] 83 [2] 5? 5? 5? 8B [1] 68 [4] 5? 89 [3] E8 [4] 6A [1] 8B [1] 6A [1] 5? E8 [4] 5? E8 [4] 99 5? 8B [1] 89 [3] E8 [4] 8D [2] 5? E8 [4] 5? 6A [1] 8B [1] 5? 5? E8 [4] 5? E8 [4] 83 [2] 85 [1] 0F 84 [4] B8 [4] 66 [2] 0F 85 [4] 8B [2] 89 [3] 81 F? [4] 0F 8F }

	condition:
		any of them
}

private rule id_21
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 81 C? [4] 8D [2] 5? 68 [4] E8 [4] FF 7? [1] 8B [1] 03 [1] 5? 8B [2] 03 [1] 5? E8 [4] 8B [3] 8D [2] 8B [3] 83 [2] 4? 89 [3] 0F B7 [2] 3B [1] 72 [1] 68 [4] E8 [4] 83 [2] B9 [4] 85 [1] 0F 84 }
		$a1 = { 81 C? [4] 8D [2] 5? 68 [4] E8 [4] FF 7? [1] 8B [1] 03 [1] 5? 8B [2] 03 [1] 5? E8 [4] 8B [3] 8D [2] 8B [3] 83 [2] 4? 89 [3] 0F B7 [2] 3B [1] 7C [1] 68 [4] E8 [4] 83 [2] B9 [4] 85 [1] 0F 84 }

	condition:
		any of them
}

private rule id_22
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8D [6] 8D [3] 8D [2] 5? 68 [4] E8 [4] 8B [2] 8B [1] 8B [2] 5? 03 [1] 5? 03 [1] 5? E8 [4] 8B [3] 8B [3] 0F B7 [3] 4? 83 [2] 83 [2] 89 [3] 3B [1] 72 [1] 8B }

	condition:
		any of them
}

private rule id_23
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 68 [4] E8 [4] 8B [3] 5? 5? 5? 89 [3] E8 [4] 33 [1] 83 [2] 8D [6] C7 [7] 66 [4] 73 [1] 8D [2] 9? 8D [2] 5? 68 [4] E8 [4] 8B [2] 8B [1] 8B [2] 5? 03 [1] 5? 03 [1] 5? E8 [4] 8B [3] 8B [3] 0F B7 [3] 4? 83 [2] 83 [2] 89 [3] 3B [1] 7C }

	condition:
		any of them
}

private rule id_24
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 45 [3] 48 [6] 4C [2] 49 [2] E8 [4] 41 [3] 41 [2] 44 [2] 85 [1] 4C [3] 44 [3] 49 [2] 66 [9] 41 [2] 48 [2] 49 [2] BA [4] 49 [2] 8B [2] 48 [2] 74 [1] 0F B7 [2] 49 [2] FF 1? [4] 48 [2] 8B [1] FF 1? [4] 48 [3] 48 [6] 4C [2] 48 [2] E8 [4] BA [4] 48 [2] EB }

	condition:
		any of them
}

private rule id_25
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 5? 8B [1] 6A [1] 68 [4] 64 [5] 5? 81 E? [4] A1 [4] 33 [1] 89 [2] 5? 5? 5? 5? 8D [2] 64 [5] 8B [1] 68 [4] 8D [5] 6A [1] 5? E8 [4] 5? 8D [5] E8 [4] C7 [6] 83 [3] 0F 84 [4] 8D [5] 5? 8D [5] E8 [4] 0F 10 [1] F3 [4] 66 [3] 0F 11 [5] 66 [4] 66 [3] 66 [7] 89 [5] 8D [2] 5? E8 [4] 8B [1] 83 [2] 85 [1] 74 [1] 5? 6A [1] 5? E8 [4] 83 [2] EB }

	condition:
		any of them
}

private rule id_26
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 68 [4] E8 [4] 83 [2] 89 [3] FF 7? [2] 5? 5? E8 [4] 33 [1] C7 [7] 83 [2] 66 [4] 73 [1] 81 C? [4] 03 [1] 0F 1F [5] 8D [2] 5? 68 [4] E8 [4] FF 7? [1] 8B [1] 03 [1] 5? 8B [2] 03 [1] 5? E8 [4] 8B [3] 8D [2] 8B [3] 83 [2] 4? 89 [3] 0F B7 [3] 3B [1] 72 }
		$a1 = { 68 [4] E8 [4] 83 [2] 89 [3] FF 7? [2] 5? 5? E8 [4] 33 [1] C7 [7] 83 [2] 66 [4] 73 [1] 81 C? [4] 03 [1] 0F 1F [6] 8D [2] 5? 68 [4] E8 [4] FF 7? [1] 8B [1] 03 [1] 5? 8B [2] 03 [1] 5? E8 [4] 8B [3] 8D [2] 8B [3] 83 [2] 4? 89 [3] 0F B7 [3] 3B [1] 7C }

	condition:
		any of them
}

private rule id_27
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 5? 8B [1] 83 [2] 5? 8B [2] 5? 5? 8B [2] 03 [1] 81 3? [4] 0F 85 [4] 33 [1] 6A [1] 5? 89 [2] 89 [2] 89 [2] 89 [2] 8D [2] 5? E8 [4] 83 [2] 8D [2] 5? 8D [2] 5? 6A [1] 6A [1] 6A [1] 6A [1] 6A [1] 6A [1] 6A [1] 68 [4] FF 1? [4] 85 [1] 0F 84 [4] 6A [1] 68 [4] 6A [1] 6A [1] FF 1? [4] 8B [1] C7 [5] 8B [2] 5? 5? 89 [2] FF 1? [4] 85 [1] 0F 84 }

	condition:
		any of them
}

private rule id_28
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 6A [1] 8D [2] 0F 57 [1] 6A [1] 5? F3 [4] E8 [4] 83 [2] 8D [2] 5? 8D [2] 5? 6A [1] 6A [1] 6A [1] 6A [1] 6A [1] 6A [1] 6A [1] 68 [4] FF 1? [4] 85 [1] 0F 84 [4] 6A [1] 68 [4] 6A [1] 6A [1] FF 1? [4] 8B [1] 5? 89 [2] C7 [5] FF 7? [1] FF 1? [4] 85 [1] 0F 84 [4] 6A [1] 68 [4] FF 7? [1] FF 7? [1] FF 7? [1] FF 1? [4] 6A [1] 89 [2] FF 7? [1] 5? 5? FF 7? [1] FF 1? [4] 33 [1] 33 [1] 66 [3] 73 }

	condition:
		any of them
}

private rule id_29
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [5] 8D [5] C7 [9] 6A [1] 8B [2] 03 [1] 8B [6] B8 [4] 83 [3] 0F 45 [5] 83 [2] 0B [1] 5? E8 [4] 8D [5] 89 [5] 8B [5] 8B [2] 8B [6] 85 [1] 74 [1] 8B [1] FF 5? [1] 5? 8D [5] C6 [3] E8 [4] 88 [5] C6 [3] 8B [5] 8B [2] F6 [7] 75 }

	condition:
		any of them
}

private rule id_30
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [6] 33 [1] 89 [2] 89 [2] 5? 5? 85 [1] 0F 84 [4] 03 [1] 89 [2] 8D [2] 8B [2] 8D [2] 89 [2] 89 [2] 85 [1] 74 }

	condition:
		any of them
}

private rule id_31
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8D [2] 5? 68 [4] E8 [4] FF 7? [1] 8B [1] 03 [1] 5? 8B [2] 03 [1] 5? E8 [4] 8B [3] 8D [2] 8B [3] 83 [2] 4? 89 [3] 0F B7 [2] 3B [1] 72 [1] 68 [4] E8 [4] 83 [2] B9 [4] 85 [1] 0F 84 }
		$a1 = { 8D [2] 5? 68 [4] E8 [4] FF 7? [1] 8B [1] 03 [1] 5? 8B [2] 03 [1] 5? E8 [4] 8B [3] 8D [2] 8B [3] 83 [2] 4? 89 [3] 0F B7 [2] 3B [1] 7C [1] 68 [4] E8 [4] 83 [2] B9 [4] 85 [1] 0F 84 }
		$b0 = { 3B [3] 0F 84 }

	condition:
		any of ($a*) and any of ($b*)
}

private rule id_32
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 68 [4] E8 [4] 8B [3] 5? 5? 5? 89 [3] E8 [4] 33 [1] 83 [2] C7 [7] 66 [4] 73 [1] 8D [6] 8D [3] 8D [2] 5? 68 [4] E8 [4] 8B [2] 8B [1] 8B [2] 5? 03 [1] 5? 03 [1] 5? E8 [4] 8B [3] 8B [3] 0F B7 [3] 4? 83 [2] 83 [2] 89 [3] 3B [1] 72 }

	condition:
		any of them
}

private rule id_33
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 81 3? [5] 4C [3] 4C [4] 0F 85 [4] 48 [6] 4C [4] 4D [3] 48 [6] 33 [1] 4C [7] 48 [2] 49 [2] 39 [1] 48 [3] E8 [4] 48 [6] FF 1? [4] 48 [2] 48 [6] FF 1? [4] 49 [3] 48 [6] FF D? 41 [3] 41 [5] 41 [5] 49 [2] FF 1? [4] 48 [2] 48 [2] 75 [1] 48 [2] 75 }

	condition:
		any of them
}

private rule id_34
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 5? 8B [1] 83 [2] A1 [4] 33 [1] 89 [2] 5? 8B [1] 5? 5? 89 [2] 8B [2] 03 [1] 81 3? [4] 0F 85 [4] 6A [1] 8D [2] 0F 57 [1] 6A [1] 5? 0F 11 [2] E8 [4] 83 [2] 8D [2] 5? 8D [2] 5? 6A [1] 6A [1] 6A [1] 6A [1] 6A [1] 6A [1] 6A [1] 68 [4] FF 1? [4] 85 [1] 0F 84 [4] 6A [1] 68 [4] 6A [1] 6A [1] FF 1? [4] 8B [1] 5? 89 [2] C7 [5] FF 7? [1] FF 1? [4] 85 [1] 0F 84 }

	condition:
		any of them
}

private rule id_35
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 33 [1] 6A [1] 5? 89 [2] 89 [2] 89 [2] 89 [2] 8D [2] 5? E8 [4] 83 [2] 8D [2] 5? 8D [2] 5? 6A [1] 6A [1] 6A [1] 6A [1] 6A [1] 6A [1] 6A [1] 68 [4] FF 1? [4] 85 [1] 0F 84 [4] 6A [1] 68 [4] 6A [1] 6A [1] FF 1? [4] 8B [1] C7 [5] 8B [2] 5? 5? 89 [2] FF 1? [4] 85 [1] 0F 84 [4] 8B [2] 8B [2] 8B [2] 6A [1] 68 [4] 5? 5? 5? FF 1? [4] 8B [2] 6A [1] 89 [2] 8B [2] 5? 5? 5? 5? FF 1? [4] 33 [1] 33 [1] 66 [3] 73 }

	condition:
		any of them
}

private rule id_36
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 5? 8B [1] 83 [2] A1 [4] 33 [1] 89 [2] 5? 8B [1] 5? 5? 89 [2] 8B [2] 03 [1] 81 3? [4] 0F 85 [4] 6A [1] 8D [2] 0F 57 [1] 6A [1] 5? F3 [4] E8 [4] 83 [2] 8D [2] 5? 8D [2] 5? 6A [1] 6A [1] 6A [1] 6A [1] 6A [1] 6A [1] 6A [1] 68 [4] FF 1? [4] 85 [1] 0F 84 [4] 6A [1] 68 [4] 6A [1] 6A [1] FF 1? [4] 8B [1] 5? 89 [2] C7 [5] FF 7? [1] FF 1? [4] 85 [1] 0F 84 }

	condition:
		any of them
}

private rule id_37
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [1] 03 [3] 6A [1] FF 7? [1] 5? 8B [2] 03 [3] 5? FF 7? [2] FF 1? [4] 8B [3] 8D [2] 0F B7 [2] 4? 89 [3] 3B [1] 7C [1] 8B [3] 8D [3] 6A [1] 6A [1] 5? 8B [5] 83 [2] 5? FF 7? [2] FF 1? [4] 8B [2] 03 [3] 5? 89 [5] FF 7? [2] FF 1? [4] FF 7? [2] FF 1? [4] 8B [6] 33 [1] 5? 5? 33 [1] E8 [4] 8B [1] 5? C2 }

	condition:
		any of them
}

private rule id_38
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [2] 83 [2] 03 [1] 89 [2] 8D [2] 03 [1] 83 [2] 75 [1] 8B [2] 8B [2] 83 [2] 83 [2] 89 [2] 89 [2] 3B [2] 0F 82 [4] B0 [1] 5? 5? 5? 8B [1] 5? C3 }

	condition:
		any of them
}

private rule id_39
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8D [2] 03 [1] 89 [2] 0F 1F [2] 83 [3] 75 }
		$b0 = { 8B [2] 03 [1] 5? 68 [4] 89 [2] E8 [4] 8B [2] 83 [2] 8B [1] 85 [1] 0F 44 [1] 8D [2] 2B [1] 8D [2] 89 [2] 66 }

	condition:
		any of ($a*) and any of ($b*)
}

private rule id_40
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 5? 8B [1] 83 [2] 83 [2] 5? 5? 5? 8B [1] 68 [4] 5? 89 [3] E8 [4] 6A [1] 8B [1] 6A [1] 5? E8 [4] 83 [2] 5? E8 [4] 83 [2] 99 8B [1] 5? E8 [4] 83 [2] 8D [2] 5? E8 [4] 83 [2] 89 [3] 5? 6A [1] 5? 5? E8 [4] 5? E8 [4] 8B [3] 83 [2] 85 [1] 0F 84 [4] B8 [4] 66 [2] 0F 85 [4] 8B [2] 3D [4] 0F 8F }

	condition:
		any of them
}

private rule id_41
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [2] 03 [1] 5? 68 [4] 89 [2] E8 [4] 8B [1] 83 [2] 8B [2] 8D [2] 85 [1] 89 [2] 0F 44 [1] 83 [2] 8D [2] 74 [1] 8B [1] 8B [1] 2B [1] 89 [2] 8B [1] 39 [1] 75 }

	condition:
		any of them
}

private rule id_42
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 83 [3] 75 [1] 83 [2] 0F 84 [4] 8B [2] 03 [1] 5? 68 [4] 89 [2] E8 [4] 8B [2] 83 [2] 8B [1] 85 [1] 0F 44 [1] 8D [2] 2B [1] 8D [2] 89 [2] 8D }

	condition:
		any of them
}

private rule id_43
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 6A [1] 8D [2] 0F 57 [1] 6A [1] 5? 0F 11 [2] E8 [4] 83 [2] 8D [2] 5? 8D [2] 5? 6A [1] 6A [1] 6A [1] 6A [1] 6A [1] 6A [1] 6A [1] 68 [4] FF 1? [4] 85 [1] 0F 84 [4] 6A [1] 68 [4] 6A [1] 6A [1] FF 1? [4] 8B [1] 5? 89 [2] C7 [5] FF 7? [1] FF 1? [4] 85 [1] 0F 84 [4] 6A [1] 68 [4] FF 7? [1] FF 7? [1] FF 7? [1] FF 1? [4] 6A [1] 89 [2] FF 7? [1] 5? 5? FF 7? [1] FF 1? [4] 33 [1] 33 [1] 66 [3] 73 }

	condition:
		any of them
}

private rule id_44
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 33 [1] 8D [5] E8 [4] 8B [2] 99 03 [1] 13 [2] 5? 5? 5? 8B [1] 5? E8 [4] 8D [5] E8 [4] 85 [1] 75 [1] 8B [5] 8B [2] 8B [6] 8D [6] 83 [2] 83 [3] 75 }

	condition:
		any of them
}

private rule id_45
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 5? 8B [1] 6A [1] 68 [4] 64 [5] 5? 81 E? [4] A1 [4] 33 [1] 89 [2] 5? 5? 5? 5? 8D [2] 64 [5] 8B [1] 68 [4] 8D [5] 6A [1] 5? E8 [4] 5? 8D [5] E8 [4] C7 [6] 83 [3] 0F 84 [4] 8D [5] 5? 8D [5] E8 [4] F3 [3] F3 [4] 66 [3] F3 [7] 66 [4] 66 [3] 66 [7] 89 [5] 8D [2] 5? E8 [4] 8B [1] 83 [2] 85 [1] 74 [1] 5? 6A [1] 5? E8 [4] 83 [2] EB }

	condition:
		any of them
}

private rule id_46
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8D [5] 0F 1F [3] 8B [1] 03 [3] 6A [1] FF 7? [1] 5? 8B [2] 03 [3] 5? FF 7? [2] FF 1? [4] 8B [3] 8D [2] 0F B7 [2] 4? 89 [3] 3B [1] 7C [1] 8B [3] 8D [3] 6A [1] 6A [1] 5? 8B [5] 83 [2] 5? FF 7? [2] FF 1? [4] 8B [2] 03 [3] 5? 89 [5] FF 7? [2] FF 1? [4] FF 7? [2] FF 1? }

	condition:
		any of them
}

private rule id_47
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 83 [2] 03 [1] 5? 5? FF 1? [4] 5? FF 1? [4] 8B [1] 5? 5? 68 [4] E8 [4] 8B [2] 83 [2] 8B [2] 8B [2] 89 [1] 8B [2] 8B [2] 83 [2] 03 [1] 89 [2] 8D [2] 03 [1] 83 [2] 75 [1] 8B [2] 8B [2] 83 [2] 83 [2] 89 [2] 89 [2] 3B [2] 0F 82 }

	condition:
		any of them
}

private rule id_48
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [2] 03 [1] 5? 68 [4] 89 [2] E8 [4] 8B [2] 83 [2] 8B [1] 85 [1] 0F 44 [1] 8D [2] 2B [1] 8D [2] 89 [2] 66 [5] 8B [2] 83 [3] 7D [1] 0F B7 [1] 5? FF 7? [1] FF 1? [4] 5? FF 1? [4] 8B [1] 5? FF 3? 68 [4] E8 [4] 8B [2] 83 [2] 89 [2] 8B [2] EB }

	condition:
		any of them
}

private rule id_49
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [2] 03 [1] 5? 68 [4] 89 [2] E8 [4] 8B [1] 83 [2] 8B [2] 8D [2] 85 [1] 89 [2] 0F 44 [1] 83 [2] 8D [2] 74 }
		$b0 = { 8B [2] 83 [2] 83 [2] 89 [2] 89 [2] 3B [2] 0F 82 [4] 5? 5? B0 [1] 5? 8B [1] 5? C3 }

	condition:
		any of ($a*) and any of ($b*)
}

private rule id_50
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [2] 03 [1] 5? 68 [4] 89 [2] E8 [4] 8B [2] 83 [2] 8B [1] 85 [1] 0F 44 [1] 8D [2] 2B [1] 8D [2] 89 [2] 8D [5] 8B [2] F7 [6] 74 [1] 0F B7 [1] 5? FF 7? [1] FF 1? [4] 5? FF 1? [4] 8B [1] 5? FF 3? 68 [4] E8 [4] 8B [2] 83 [2] 89 [2] 8B [2] EB }

	condition:
		any of them
}

private rule id_51
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [2] 3D [4] 0F 8F [4] 81 3? [5] 8D [2] 89 [3] 0F 85 [4] 8B [2] 8D [5] 03 [1] 89 [3] 33 [1] 5? 68 [4] 39 [1] 0F 44 [1] E8 [4] 8B [3] 83 [2] 6A [1] 68 [4] FF 7? [1] 5? FF 1? [4] 8B [1] 85 [1] 75 }

	condition:
		any of them
}

private rule id_52
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 83 [2] 75 [1] 83 [3] 0F 84 [4] 8B [2] 03 [1] 5? 68 [4] 89 [3] E8 [4] 8B [3] 83 [2] 8B [1] 85 [1] 8B [2] 8B [1] 0F 45 [1] 33 [1] 89 [3] 03 }

	condition:
		any of them
}

private rule id_53
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 5? 8B [1] 6A [1] 68 [4] 64 [5] 5? 83 [2] 5? 5? A1 [4] 33 [1] 5? 8D [2] 64 [5] 8B [1] 89 [2] C7 [6] C7 [5] C7 [6] C7 [6] 5? 8D [2] C7 [6] 5? C7 [6] E8 [4] C7 [6] 8B [1] 89 [2] 8B [2] C7 [6] 8B [1] 8B [2] 8D [2] 89 [3] 8B [1] E8 [4] 6A [1] 6A [1] 8B [1] C7 [5] E8 [4] 83 [2] C6 [3] 8B [1] FF 7? [1] E8 [4] 85 [1] 75 [1] 8B [1] 6A [1] 8B [2] 03 [1] 8B [2] 83 [2] 8B [1] 83 [2] 83 [3] 0F 45 [1] 5? E8 [4] 8B [1] 8B [2] 64 [6] 5? 5? 5? 8B [1] 5? C2 }

	condition:
		any of them
}

private rule id_54
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 5? 8B [1] 6A [1] 68 [4] 64 [5] 5? 81 E? [4] 5? 5? 5? A1 [4] 33 [1] 5? 8D [2] 64 [5] 8B [2] 5? 8D [5] 5? E8 [4] 33 [1] 89 [2] 39 [2] 0F 84 [4] 8B [5] 8B [2] F6 [7] 75 [1] 8B [6] 8B [1] 8B [2] 6A [1] 6A [1] 5? 5? 8D [2] 5? FF D? 8B [2] EB }

	condition:
		any of them
}

private rule id_55
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8D [2] 89 [2] 8B [1] 8B [2] C7 [6] 8B [1] 8B [2] 8D [2] 89 [3] 8B [1] 8B [2] C7 [6] 8B [1] 8B [2] 8D [2] 89 [3] C7 [6] 8B [1] 6A [1] 8B [2] C7 [6] 8B [1] 8B [2] 8D [2] 89 [3] 8D [2] 89 [2] C7 [5] E8 [4] 8B [1] 0F 57 [1] 83 [2] 66 [3] 6A [1] C6 [3] E8 [4] 89 [2] 83 [2] 8D [2] 8D [2] 89 [2] 89 [2] 8D [2] 8B [2] 8D [2] 89 [2] 8D [2] 8B [2] 8D [2] 83 [2] C7 [5] C6 [3] C6 [3] 8B [2] 89 [2] 8B [2] 8B [2] 89 [2] 89 [2] 89 [2] 89 [2] 89 [2] 8B [2] C7 [5] C7 [5] C7 [5] A1 [4] C7 [5] 8B [2] C7 [5] C7 [5] 89 [2] A1 [4] C7 [6] 89 [2] C7 [6] C6 [3] 6A [1] 6A [1] FF 7? [1] E8 [4] 83 [2] 85 [1] 74 [1] 6A [1] 5? 8B [1] E8 [4] 8B [2] 8B [2] 89 [2] 8B [1] FF 5? [1] 8D [2] C6 [3] 5? E8 [4] 83 [2] 8B [1] 5? E8 [4] 8B [2] 85 [1] 74 [1] 8B [1] FF 5? [1] 85 [1] 74 }

	condition:
		any of them
}

private rule id_56
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [2] 03 [1] 5? 68 [4] 89 [2] E8 [4] 8B [1] 83 [2] 8B [2] 85 [1] 8D [2] 89 [2] 0F 44 [1] 33 [1] 03 [1] 89 [2] 89 [2] 39 [1] 74 [1] 8B [1] 39 [1] 75 [1] 85 [1] 78 }

	condition:
		any of them
}

private rule id_57
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 68 [4] E8 [4] FF 7? [2] 89 [3] 5? 5? E8 [4] 33 [1] C7 [7] 83 [2] 66 [4] 73 [1] 81 C? [4] 03 [1] 8B [1] 8D [2] 5? 68 [4] E8 [4] FF 7? [1] 8B [1] 03 [1] 5? 8B [2] 03 [1] 5? E8 [4] 8B [3] 8D [2] 8B [3] 83 [2] 4? 89 [3] 0F B7 [3] 3B [1] 72 }

	condition:
		any of them
}

private rule id_58
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 81 C? [4] 03 [1] 8D [2] 8D [2] 5? 68 [4] E8 [4] FF 7? [1] 8B [1] 03 [1] 5? 8B [2] 03 [1] 5? E8 [4] 8B [3] 8D [2] 8B [3] 83 [2] 4? 89 [3] 0F B7 [3] 3B [1] 7C [1] 8B }

	condition:
		any of them
}

private rule id_59
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [2] 03 [1] 5? 68 [4] 89 [3] E8 [4] 8B [2] 83 [2] 8B [1] 85 [1] 8B [1] 8D [2] 0F 45 [1] 89 [3] 89 [3] 33 [1] 89 [3] 8D [2] 8B [1] 85 [1] 74 [1] 8B [1] 89 [3] 8B [1] 3B [1] 75 }

	condition:
		any of them
}

private rule id_60
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [2] 03 [1] 5? 68 [4] 89 [3] E8 [4] 8B [3] 83 [2] 8B [1] 85 [1] 8B [2] 8B [1] 0F 45 [1] 33 [1] 89 [3] 03 [1] 03 [1] 89 [3] 8B [1] 89 [3] 83 [3] 7D [1] 0F B7 [2] 5? 5? FF 1? [4] 5? FF 1? [4] 8B [1] 5? FF 3? [1] 68 [4] E8 [4] 8B [3] 83 [2] 8B [3] 89 [1] EB }

	condition:
		any of them
}

private rule id_61
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [2] 8B [1] 03 [2] 8B [2] 03 [2] 6A [1] 5? 8B [2] 5? 5? 5? FF 1? [4] 0F B7 [2] 4? 83 [2] 3B [1] 7C [1] 8B [2] 8B [5] 8B [2] 6A [1] 6A [1] 8D [2] 5? 83 [2] 5? 5? FF 1? [4] 8B [2] 03 [2] 5? 89 [5] 8B [2] 5? FF 1? [4] 8B [2] 5? FF 1? }

	condition:
		any of them
}

private rule id_62
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [2] 8B [1] 6A [1] 83 [2] 5? E8 [4] 8D [2] 89 [2] 8B [1] 8B [2] C7 [6] 8B [1] 8B [2] 8D [2] 89 [3] 8B [1] 8B [2] C7 [6] 8B [1] 8B [2] 8D [2] 89 [3] C7 [6] 8B [1] 6A [1] 8B [2] C7 [6] 8B [1] 8B [2] 8D [2] 89 [3] 8D [2] 89 [2] C7 [5] E8 [4] 8B [1] 0F 57 [1] 83 [2] 66 [3] 6A [1] C6 [3] E8 [4] 89 [2] 83 [2] 8D [2] 8D [2] 89 [2] 89 [2] 8D [2] 8B [2] 8D [2] 89 [2] 8D [2] 8B [2] 8D [2] 83 [2] C7 [5] C6 [3] C6 [3] 8B [2] 89 [2] 8B [2] 8B [2] 89 [2] 89 [2] 89 [2] 89 [2] 89 [2] 8B [2] C7 [5] C7 [5] C7 [5] A1 [4] C7 [5] 8B [2] C7 [5] C7 [5] 89 [2] A1 [4] C7 [6] 89 [2] C7 [6] C6 [3] 6A [1] 6A [1] FF 7? [1] E8 [4] 83 [2] 85 [1] 74 [1] 6A [1] 5? 8B [1] E8 [4] 8B [2] 8B [2] 89 [2] 8B [1] FF 5? [1] 8D [2] C6 [3] 5? E8 [4] 83 [2] 8B [1] 5? E8 [4] 8B [2] 85 [1] 74 }

	condition:
		any of them
}

private rule id_63
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [2] 03 [1] 5? 68 [4] 89 [2] E8 [4] 8B [1] 83 [2] 8B [2] 85 [1] 8D [2] 89 [2] 0F 44 [1] 33 [1] 03 [1] 89 [2] 89 [2] 39 [1] 74 }
		$b0 = { 8B [2] 8B [2] 83 [2] 83 [2] 89 [2] 89 [2] 3B [2] 0F 82 [4] B0 [1] 5? 5? 5? 8B [1] 5? C3 }

	condition:
		any of ($a*) and any of ($b*)
}

private rule id_64
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 81 C? [4] 03 [1] 8B [1] 8D [2] 5? 68 [4] E8 [4] FF 7? [1] 8B [1] 03 [1] 5? 8B [2] 03 [1] 5? E8 [4] 8B [3] 8D [2] 8B [3] 83 [2] 4? 89 [3] 0F B7 [3] 3B [1] 72 [1] 8B }

	condition:
		any of them
}

private rule id_65
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 68 [4] E8 [4] FF 7? [2] 89 [3] 5? 5? E8 [4] 33 [1] C7 [7] 83 [2] 66 [4] 73 [1] 81 C? [4] 03 [1] 8D [2] 8D [2] 5? 68 [4] E8 [4] FF 7? [1] 8B [1] 03 [1] 5? 8B [2] 03 [1] 5? E8 [4] 8B [3] 8D [2] 8B [3] 83 [2] 4? 89 [3] 0F B7 [3] 3B [1] 7C }

	condition:
		any of them
}

private rule id_66
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8D [2] 03 [1] 5? FF 7? [2] FF 1? [4] 5? FF 1? [4] 8B [1] 5? 5? 68 [4] E8 [4] 8B [3] 83 [2] 8B [3] 89 [1] 8B [3] 8B [3] 83 [2] 83 [2] 89 [3] 03 [1] 89 [3] 03 [1] 89 [3] 8B [1] 85 [1] 75 [1] 8B [3] 8B [3] 83 [2] 83 [2] 89 [3] 89 [3] 3B [3] 0F 82 }

	condition:
		any of them
}

private rule id_67
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [2] 3D [4] 0F 8F [4] 81 3? [5] 8D [2] 89 [3] 0F 85 [4] 8B [2] 8D [5] 03 [1] 89 [3] 33 [1] 5? 68 [4] 39 [1] 0F 44 [1] E8 [4] 83 [2] 68 [4] FF 1? [4] 8B [3] FF 7? [1] 6A [1] 68 [4] 5? FF 1? [4] FF D? 8B [3] 6A [1] 68 [4] FF 7? [1] 5? FF 1? [4] 8B [1] 85 [1] 75 }

	condition:
		any of them
}

private rule id_68
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 5? 8B [1] 6A [1] 68 [4] 64 [5] 5? 83 [2] 5? 5? 5? A1 [4] 33 [1] 5? 8D [2] 64 [5] 8B [1] 89 [2] 89 [2] 8B [2] 89 [2] C7 [6] C7 [5] C7 [6] 89 [2] C7 [6] C7 [6] 8B [1] 6A [1] 6A [1] C7 [6] 8B [2] C7 [6] 8B [1] 8B [2] 8D [2] 89 [3] 8B [1] C7 [6] C7 [6] 8B [2] 03 [1] 8B [1] C7 [6] C7 [6] C7 [6] C7 [6] C7 [6] C7 [6] C7 [6] C7 [6] C7 [6] C7 [6] E8 [4] 6A [1] E8 [4] 8B [1] 0F 57 [1] 83 [2] 66 [3] 6A [1] C7 [6] E8 [4] 89 [2] 83 [2] 8D [2] 89 [2] 89 [2] C7 [6] 8B [2] 89 [2] 89 [2] 8B [1] FF 5? [1] 8D [2] C7 [6] 5? E8 [4] 83 [2] 8B [1] 8B [1] 6A [1] 8B [2] FF D? C6 [3] 8B [2] 88 [2] 85 [1] 74 [1] 8B [1] FF 5? [1] 8B [1] 85 [1] 74 [1] 8B [1] 6A [1] FF 1? }

	condition:
		any of them
}

private rule id_69
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8D [2] 03 [1] 89 [2] 0F 1F [2] 83 [3] 75 }
		$b0 = { 8B [2] 03 [1] 5? 68 [4] 89 [2] E8 [4] 8B [1] 83 [2] 8B [2] 85 [1] 8D [2] 89 [2] 0F 44 [1] 33 [1] 03 [1] 89 [2] 89 [2] 39 [1] 74 }

	condition:
		any of ($a*) and any of ($b*)
}

private rule id_70
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 83 [3] 75 [1] 83 [2] 0F 84 [4] 8B [2] 03 [1] 5? 68 [4] 89 [3] E8 [4] 8B [2] 83 [2] 8B [1] 85 [1] 8B [1] 8D [2] 0F 45 [1] 89 [3] 89 [3] 33 [1] 89 [3] 8D [2] 8B [1] 85 [1] 74 }

	condition:
		any of them
}

private rule id_71
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 81 3? [5] 8D [2] 89 [3] 0F 85 [4] 8B [2] 8D [5] 03 [1] 89 [3] 33 [1] 5? 68 [4] 39 [1] 0F 44 [1] E8 [4] 83 [2] 68 [4] FF 1? [4] 8B [3] FF 7? [1] 6A [1] 68 [4] 5? FF 1? [4] FF D? 8B [3] 6A [1] 68 [4] FF 7? [1] 5? FF 1? [4] 8B [1] 85 [1] 75 [1] 85 [1] 75 }

	condition:
		any of them
}

private rule id_72
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [2] 8B [1] 6A [1] 83 [2] 5? E8 [4] 8D [2] 89 [2] 8B [1] 8B [2] C7 [6] 8B [1] 8B [2] 8D [2] 89 [3] 8B [1] 8B [2] C7 [6] 8B [1] 8B [2] 8D [2] 89 [3] C7 [6] 8B [1] 6A [1] 8B [2] C7 [6] 8B [1] 8B [2] 8D [2] 89 [3] 8D [2] 89 [2] C7 [5] E8 [4] 8B [1] 0F 57 [1] 83 [2] 66 [3] 6A [1] C6 [3] E8 [4] 89 [2] 83 [2] 8D [2] 8D [2] 89 [2] 89 [2] 8D [2] 8B [2] 8D [2] 89 [2] 8D [2] 8B [2] 8D [2] 83 [2] C7 [5] C6 [3] C6 [3] 8B [2] 89 [2] 8B [2] 8B [2] 89 [2] 89 [2] 89 [2] 89 [2] 89 [2] 8B [2] C7 [5] C7 [5] C7 [5] A1 [4] C7 [5] 8B [2] C7 [5] C7 [5] 89 [2] A1 [4] C7 [6] 89 [2] C7 [6] C6 [3] 6A [1] 6A [1] FF 7? [1] E8 [4] 83 [2] 85 [1] 74 }
		$b0 = { 8B [2] 6A [1] 8B [1] 8B [2] 33 [1] 03 [1] 39 [2] 0F 94 [1] 8D [6] 0B [2] 5? E8 [4] 8B [1] 8B [2] 64 [6] 5? 5? 5? 5? 8B [1] 5? C2 }

	condition:
		any of ($a*) and any of ($b*)
}

private rule id_73
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 83 [3] 75 [1] 83 [2] 0F 84 [4] 8B [2] 03 [1] 5? 68 [4] 89 [2] E8 [4] 8B [1] 83 [2] 8B [2] 85 [1] 8D [2] 89 [2] 0F 44 [1] 33 [1] 03 [1] 89 [2] 89 [2] 39 [1] 74 }

	condition:
		any of them
}

private rule id_74
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 81 3? [5] 8D [2] 89 [3] 0F 85 [4] 8B [2] 8D [5] 03 [1] 89 [3] 33 [1] 5? 68 [4] 39 [1] 0F 44 [1] E8 [4] 8B [3] 83 [2] 6A [1] 68 [4] FF 7? [1] 5? FF 1? [4] 8B [1] 85 [1] 75 [1] 85 [1] 75 }

	condition:
		any of them
}

private rule id_75
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [2] 8D [5] 03 [1] 89 [3] 33 [1] 5? 68 [4] 39 [1] 0F 44 [1] E8 [4] 83 [2] 68 [4] FF 1? [4] 8B [3] FF 7? [1] 6A [1] 68 [4] 5? FF 1? [4] FF D? 8B [3] 6A [1] 68 [4] FF 7? [1] 5? FF 1? [4] 8B [1] 85 [1] 75 [1] 85 [1] 75 [1] FF 7? [2] 68 [4] E8 [4] 83 [2] 32 [1] 5? 5? 5? 8B [1] 5? C3 }

	condition:
		any of them
}

rule RunPE_In_Memory
{
	meta:
		author = "Paul"
		date = "June 2020"
	condition:
		(id_1 or id_2 or id_3 or id_4 or id_5 or id_6 or id_7 or id_8 or id_9 or id_10 or id_11 or id_12 or id_13 or id_14 or id_15 or id_16 or id_17 or id_18 or id_19 or id_20 or id_21 or id_22 or id_23 or id_24 or id_25 or id_26 or id_27 or id_28 or id_29 or id_30 or id_31 or id_32 or id_33 or id_34 or id_35 or id_36 or id_37 or id_38 or id_39 or id_40 or id_41 or id_42 or id_43 or id_44 or id_45 or id_46 or id_47 or id_48 or id_49 or id_50 or id_51 or id_52 or id_53 or id_54 or id_55 or id_56 or id_57 or id_58 or id_59 or id_60 or id_61 or id_62 or id_63 or id_64 or id_65 or id_66 or id_67 or id_68 or id_69 or id_70 or id_71 or id_72 or id_73 or id_74 or id_75)
}
