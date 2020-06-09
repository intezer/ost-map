private rule id_1
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { BA [4] 6B [2] 0F B6 [3] 5? E8 [4] 83 [2] 0F B6 [1] C1 [2] BA [4] C1 [2] 0F B6 [3] 5? E8 [4] 83 [2] 0F B6 [1] 0B [1] BA [4] 6B [2] 8B [2] 88 [2] BA [4] D1 [1] 0F B6 [3] 5? E8 [4] 83 [2] 0F B6 [1] C1 [2] B9 [4] 6B [2] 0F B6 [3] 5? E8 [4] 83 [2] 0F B6 [1] 0B [1] BA [4] C1 [2] 8B [2] 88 [2] B9 [4] C1 [2] 0F B6 [3] 5? E8 [4] 83 [2] 0F B6 [1] C1 [2] B8 [4] 6B [2] 0F B6 [3] 5? E8 [4] 83 [2] 0F B6 [1] 0B [1] B9 [4] D1 [1] 8B [2] 88 [2] B8 [4] 6B [2] 0F B6 [3] 5? E8 [4] 83 [2] 0F B6 [1] C1 [2] B8 [4] 6B [2] 0F B6 [3] 5? E8 [4] 83 [2] 0F B6 [1] 0B [1] B9 [4] 6B [2] 8B [2] 88 [2] C7 [6] 8B [2] 5? FF 1? [4] 8B [2] 5? FF 1? [4] 8B }

	condition:
		any of them
}

private rule id_2
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [5] 83 [6] 0F 85 [4] 8D [5] 5? 6A [1] 8B [5] 81 C? [4] 5? E8 [4] 83 [2] 8D [5] 5? 8B [5] 05 [4] 5? 8B [5] 81 C? [4] 5? 8B [5] 5? 68 [4] 68 [4] 8D [5] 5? E8 [4] 83 [2] 8B [5] 83 [2] 89 [5] 83 [3] 74 [1] 8D [5] 5? E8 [4] 83 [2] EB }

	condition:
		any of them
}

private rule id_3
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 83 [3] 0F 85 [4] BA [4] 6B [2] 0F B6 [3] 5? E8 [4] 83 [2] 0F B6 [1] C1 [2] BA [4] C1 [2] 0F B6 [3] 5? E8 [4] 83 [2] 0F B6 [1] 0B [1] BA [4] 6B [2] 8B [2] 88 [2] BA [4] D1 [1] 0F B6 [3] 5? E8 [4] 83 [2] 0F B6 [1] C1 [2] B9 [4] 6B [2] 0F B6 [3] 5? E8 [4] 83 [2] 0F B6 [1] 0B [1] BA [4] C1 [2] 8B [2] 88 [2] B9 [4] C1 [2] 0F B6 [3] 5? E8 [4] 83 [2] 0F B6 [1] C1 [2] B8 [4] 6B [2] 0F B6 [3] 5? E8 [4] 83 [2] 0F B6 [1] 0B [1] B9 [4] D1 [1] 8B [2] 88 [2] B8 [4] 6B [2] 0F B6 [3] 5? E8 [4] 83 [2] 0F B6 [1] C1 [2] B8 [4] 6B [2] 0F B6 [3] 5? E8 [4] 83 [2] 0F B6 [1] 0B [1] B9 [4] 6B [2] 8B [2] 88 [2] C7 [6] 8B [2] 5? FF 1? }

	condition:
		any of them
}

private rule id_4
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 68 [4] E8 [4] 83 [2] 8B [5] 83 [6] 0F 85 [4] 8D [5] 5? 6A [1] 8B [5] 81 C? [4] 5? E8 [4] 83 [2] 8D [5] 5? 8B [5] 05 [4] 5? 8B [5] 81 C? [4] 5? 8B [5] 5? 68 [4] 68 [4] 8D [5] 5? E8 [4] 83 [2] 8B [5] 83 [2] 89 [5] 83 [3] 74 }

	condition:
		any of them
}

private rule id_5
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { C7 [6] 6A [1] 6A [1] 6A [1] 6A [1] 6A [1] 6A [1] 6A [1] 6A [1] 6A [1] 8D [2] 5? 8D [2] 5? 8B [2] 5? FF 1? [4] 89 [2] 83 [3] 0F 85 [4] 83 [3] 0F 85 [4] BA [4] 6B [2] 0F B6 [3] 5? E8 [4] 83 [2] 0F B6 [1] C1 [2] BA [4] C1 [2] 0F B6 [3] 5? E8 [4] 83 [2] 0F B6 [1] 0B [1] BA [4] 6B [2] 8B [2] 88 [2] BA [4] D1 [1] 0F B6 [3] 5? E8 [4] 83 [2] 0F B6 [1] C1 [2] B9 [4] 6B [2] 0F B6 [3] 5? E8 [4] 83 [2] 0F B6 [1] 0B [1] BA [4] C1 [2] 8B [2] 88 [2] B9 [4] C1 [2] 0F B6 [3] 5? E8 [4] 83 [2] 0F B6 [1] C1 [2] B8 [4] 6B [2] 0F B6 [3] 5? E8 [4] 83 [2] 0F B6 [1] 0B [1] B9 [4] D1 [1] 8B [2] 88 [2] B8 [4] 6B [2] 0F B6 [3] 5? E8 [4] 83 [2] 0F B6 [1] C1 [2] B8 [4] 6B [2] 0F B6 [3] 5? E8 [4] 83 [2] 0F B6 [1] 0B [1] B9 [4] 6B [2] 8B [2] 88 [2] C7 }

	condition:
		any of them
}

private rule id_6
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [5] 83 [2] 89 [5] 83 [6] 0F 8D [4] 6A [1] 8B [2] 03 [5] 5? 8D [2] 5? E8 [4] 83 [2] 8D [2] 5? 8D [2] 5? E8 [4] 83 [2] 8D [2] 5? E8 [4] 83 [2] 8D [5] 5? 8D [2] 5? E8 [4] 83 [2] 6A [1] 8D [5] 5? 8B [5] 8D [3] 5? 8B [5] 8B [2] 8D [3] 5? E8 [4] 83 [2] 8B [5] 83 [2] 89 [5] 8B [5] 83 [2] 83 [2] 76 }

	condition:
		any of them
}

private rule id_7
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [2] 8B [5] 89 [5] C7 [9] 8D [5] 5? 8D [5] 5? B9 [4] D1 [1] 8B [2] 8B [6] 5? 8B [2] 5? 8B [2] 5? E8 [4] 83 [2] 89 [5] 83 [6] 0F 85 [4] 6A [1] 68 [4] 8B [5] 5? 6A [1] FF 1? [4] 8B [2] 89 [5] 8B [2] 83 [6] 75 }

	condition:
		any of them
}

private rule id_8
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 83 [6] 0F 84 [4] 6A [1] 68 [4] 8B [5] 5? 6A [1] FF 1? [4] 8B [2] 89 [5] 6A [1] 68 [4] 8B [5] 5? 6A [1] FF 1? [4] 8B [2] 89 [5] 8B [2] 83 [6] 74 [1] 8B [2] 83 [6] 75 }

	condition:
		any of them
}

private rule id_9
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 5? 8B [1] 81 E? [4] A1 [4] 33 [1] 89 [2] 8B [2] 8B [5] 0F B7 [1] 89 [5] 83 [6] 74 [1] 8B [2] 83 [6] 77 [1] 8B [2] C7 [9] B8 [4] E9 }

	condition:
		any of them
}

private rule id_10
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 83 [6] 0F 8D [4] 6A [1] 8B [2] 03 [5] 5? 8D [2] 5? E8 [4] 83 [2] 8D [2] 5? 8D [2] 5? E8 [4] 83 [2] 8D [2] 5? E8 [4] 83 [2] 8D [5] 5? 8D [2] 5? E8 [4] 83 [2] 6A [1] 8D [5] 5? 8B [5] 8D [3] 5? 8B [5] 8B [2] 8D [3] 5? E8 [4] 83 [2] 8B [5] 83 [2] 89 [5] 8B [5] 83 [2] 83 [2] 76 [1] B8 [4] 2B [5] 89 }

	condition:
		any of them
}

rule quarkspwdump
{
	meta:
		author = "Paul"
		date = "June 2020"
	condition:
		(id_1 or id_2 or id_3 or id_4 or id_5 or id_6 or id_7 or id_8 or id_9 or id_10)
}