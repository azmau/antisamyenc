package ro.azmau;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class MainTest {

	private Main cut;

	@BeforeEach
	void setUp() {
		this.cut = new Main();
	}

	@Test
	void firstTest() {
		String input = "duke";

		String result = cut.format(input);

		assertEquals(result, "DUKE");
	}
}
