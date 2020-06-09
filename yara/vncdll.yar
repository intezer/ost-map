private rule id_1
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 5? 8B [1] 6A [1] 68 [4] 64 [5] 5? 64 [6] 5? 5? 8B [1] 5? 5? 8D [5] 8B [1] 89 [2] E8 [4] 8B [5] C7 [6] 8B [1] 3B [1] 74 [1] 8B [1] 8B [1] 0F B7 [2] 5? FF 5? [1] 83 [6] 75 [1] 8B [1] 3B [5] 75 }
		$a1 = { 5? 8B [1] 6A [1] 68 [4] 64 [5] 5? 64 [6] 5? 5? 5? 8B [1] 8D [5] 5? 8B [1] 89 [2] E8 [4] 8B [5] 8B [1] C7 [6] 3B [1] 74 [1] 0F B7 [2] 8B [1] 8B [2] 5? 8B [1] FF D? 83 [6] 75 [1] 8B [1] 3B [5] 75 }

	condition:
		any of them
}

private rule id_2
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [2] 0F BF [1] C1 [2] 3B [1] 0F BF [1] 89 [2] 8B [2] 89 [2] 75 [1] 3B [1] 0F 84 [4] 0F B7 [1] 0F B7 [1] C1 [2] 0B [1] 0F B7 [5] 5? 5? 5? FF 1? [4] 8B [2] 8D [2] 5? 8D [2] 5? E8 [4] 5? B8 [4] 5? 8B [1] 5? C2 }
		$a1 = { 8B [2] 0F BF [1] C1 [2] 0F BF [1] 89 [2] 3B [1] 8B [2] 89 [2] 75 [1] 3B [1] 74 [1] 0F B7 [1] 0F B7 [1] 0F B7 [5] C1 [2] 0B [1] 5? 5? 5? FF 1? [4] 8D [2] 5? 8D [2] 5? 8B [2] E8 [4] 5? B8 [4] 5? 8B [1] 5? C2 }

	condition:
		any of them
}

private rule id_3
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 5? 68 [4] 8D [5] 6A [1] 5? E8 [4] 83 [2] C7 [6] 8D [5] 5? 6A [1] 6A [1] FF 1? [4] 8B [2] C7 [6] 85 [1] 74 [1] 8B [1] 8B [2] 8B [2] 2B [1] 89 [2] 8B [2] 2B [1] C7 [6] 89 [2] 89 [2] 89 [2] 5? 68 [4] C6 [6] E8 [4] 8B [1] 83 [2] 85 [1] 0F 84 }

	condition:
		any of them
}

private rule id_4
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 8B [2] 8D [2] 6A [1] 5? E8 [4] 85 [1] 0F 84 [4] 8B [2] 8B [1] 8B [1] 81 E? [4] C1 [2] 0B [1] 8B [1] C1 [2] 81 E? [4] 0B [1] C1 [2] C1 [2] 0B [1] 8D [2] 5? E8 [4] 8B [1] 83 [2] 85 [1] 0F 84 [4] 5? C6 [3] 8B [2] 5? E8 [4] 85 [1] 75 }
		$a1 = { 8B [2] 6A [1] 8D [2] 5? E8 [4] 85 [1] 0F 84 [4] 8B [2] 8B [1] 8B [1] 8B [1] 81 E? [4] C1 [2] 25 [4] C1 [2] 0B [1] 0B [1] C1 [2] C1 [2] 0B [1] 8D [2] 5? E8 [4] 8B [1] 83 [2] 85 [1] 0F 84 [4] 5? C6 [3] 8B [2] 5? E8 [4] 85 [1] 75 }

	condition:
		any of them
}

private rule id_5
{
	meta:
		author = "Intezer Labs"
	strings:
		$a0 = { 5? 8B [1] 64 [5] 6A [1] 68 [4] 5? 64 [6] 83 [3] 5? 8B [2] 5? 5? 8B [1] 74 [1] 8B [5] 2B [1] 99 33 [1] 2B [1] 75 [1] 8B [5] 2B [2] 99 33 [1] 2B [1] 74 }
		$a1 = { 5? 8B [1] 64 [5] 6A [1] 68 [4] 5? 64 [6] 83 [3] 5? 5? 5? 8B [2] 8B [1] 74 [1] 8B [5] 2B [1] 99 33 [1] 2B [1] 75 [1] 8B [5] 2B [2] 99 33 [1] 2B [1] 74 }

	condition:
		any of them
}

rule vncdll
{
	meta:
		author = "Paul"
		date = "June 2020"
	condition:
		(id_1 or id_2 or id_3 or id_4 or id_5)
}