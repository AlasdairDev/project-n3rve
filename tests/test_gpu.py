"""GPU classification: it decides hashcat's workload profile (-w 2 vs -w 4)."""

from src.gpu import _clean_gpu_name, _looks_discrete, _select_gpu

IGPU = "Intel Corporation TigerLake-LP GT2 [Iris Xe Graphics]"
DGPU = "NVIDIA Corporation GA106M [GeForce RTX 3060 Mobile]"
AMD = "Advanced Micro Devices, Inc. [AMD/ATI] Navi 22 [Radeon RX 6700 XT]"


def _g(name):
    return {"name": name, "ram_bytes": 0}


def test_discrete_matching_is_word_bounded():
    assert _looks_discrete(DGPU)
    assert _looks_discrete(AMD)
    assert _looks_discrete("Intel Corporation DG2 [Arc A770]")
    assert not _looks_discrete(IGPU)
    # "rx"/"arc" inside unrelated vendor names must not read as discrete.
    assert not _looks_discrete("Matrox Electronics Systems Ltd. MGA G200eW")
    assert not _looks_discrete("Advanced Micro Devices Arcturus GL-XL")


def test_discrete_card_wins_over_the_igpu_listed_first():
    """A laptop enumerates the iGPU first; picking it would run hashcat at the
    conservative workload profile on a machine that has a real GPU."""
    name, discrete = _select_gpu([_g(IGPU), _g(DGPU)])
    assert discrete is True
    assert "RTX 3060" in name


def test_igpu_only_reports_integrated():
    name, discrete = _select_gpu([_g(IGPU)])
    assert discrete is False
    assert "Iris Xe" in name


def test_skip_list_entries_are_not_selected_when_a_real_adapter_exists():
    name, discrete = _select_gpu([_g("Microsoft Basic Display Adapter"), _g(AMD)])
    assert discrete is True
    assert "RX 6700" in name


def test_no_adapters_returns_nothing():
    assert _select_gpu([]) == (None, False)


def test_clean_gpu_name_strips_pci_ids_and_revisions():
    line = (
        "00:02.0 VGA compatible controller [0300]: Intel Corporation "
        "TigerLake-LP GT2 [Iris Xe Graphics] [8086:9a49] (rev 01)"
    )
    assert _clean_gpu_name(line) == "Intel Corporation TigerLake-LP GT2 [Iris Xe Graphics]"
