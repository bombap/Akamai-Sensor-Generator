package akamai.bypass;

public class randomizer {
	static long randomWithRange(int min, int max) {
		int range = (max - min) + 1;
		return (long) (Math.random() * range) + min;
	}
}
