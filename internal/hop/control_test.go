package hop

import "testing"

func TestAllocateShares(t *testing.T) {
	t.Run("single edge gets full host cap", func(t *testing.T) {
		got := AllocateShares(40, map[string]float64{"e1": 10})
		if got["e1"] != 40 {
			t.Fatalf("got %v, want e1=40", got)
		}
	})

	t.Run("idle edges split evenly with full sum", func(t *testing.T) {
		got := AllocateShares(10, map[string]float64{"e1": 0, "e2": 0, "e3": 0})
		sum := got["e1"] + got["e2"] + got["e3"]
		if sum != 10 {
			t.Fatalf("sum = %d, want 10 (%v)", sum, got)
		}
		if got["e1"] != 4 || got["e2"] != 3 || got["e3"] != 3 {
			t.Fatalf("unexpected even split: %v", got)
		}
	})

	t.Run("demand weighted with starvation floor", func(t *testing.T) {
		got := AllocateShares(40, map[string]float64{"us-east": 80, "eu-west": 20})
		sum := got["us-east"] + got["eu-west"]
		if sum != 40 {
			t.Fatalf("sum = %d, want 40 (%v)", sum, got)
		}
		if got["us-east"] <= got["eu-west"] {
			t.Fatalf("expected us-east > eu-west, got %v", got)
		}
		if got["eu-west"] < 5 {
			t.Fatalf("eu-west starved below floor: %v", got)
		}
	})

	t.Run("one busy one idle keeps idle floor", func(t *testing.T) {
		got := AllocateShares(20, map[string]float64{"busy": 100, "idle": 0})
		if got["busy"]+got["idle"] != 20 {
			t.Fatalf("sum != 20: %v", got)
		}
		if got["idle"] < 2 {
			t.Fatalf("idle edge below expected floor: %v", got)
		}
		if got["busy"] < 15 {
			t.Fatalf("busy edge did not receive bulk of capacity: %v", got)
		}
	})

	t.Run("host cap smaller than edge count gives floor of 1", func(t *testing.T) {
		got := AllocateShares(2, map[string]float64{"a": 5, "b": 3, "c": 1})
		for _, id := range []string{"a", "b", "c"} {
			if got[id] != 1 {
				t.Fatalf("got[%s] = %d, want 1", id, got[id])
			}
		}
	})
}

func TestLeafStateShare_PrefersYourShare(t *testing.T) {
	st := LeafState{HostCap: 40, EdgesSeen: 2, YourShare: 31}
	if got := st.Share(); got != 31 {
		t.Fatalf("Share() = %d, want 31", got)
	}
	legacy := LeafState{HostCap: 40, EdgesSeen: 2}
	if got := legacy.Share(); got != 20 {
		t.Fatalf("legacy Share() = %d, want 20", got)
	}
}
