package ro.azmau;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.owasp.esapi.ESAPI;

class SanitizerTest {

	private Sanitizer sanitizer;

	@BeforeEach
	void setUp() {
		this.sanitizer = new Sanitizer();
	}

	@ParameterizedTest
	@CsvSource({"<div style=\"\">&nbsp;</div><script>alert(1)</script> for better &origin &or;der,<div style=\"\">&nbsp;</div> for better &origin &or;der",
			"<div style=\"\">&nbsp;</div><script>alert(1)</script> for better &gtme &gt;o,<div style=\"\">&nbsp;</div> for better &gtme &gt;o",
			"<div style=\"\">&nbsp;</div><script>alert(1)</script> for better my&language &lang;uage,<div style=\"\">&nbsp;</div> for better my&language &lang;uage"})
	final void testHtmlEntities(String value, String expected) {
		assertThat(sanitizer.clean(value)).isEqualTo(expected);
	}

	@ParameterizedTest
	@CsvSource({"<div style=\"\">&nbsp;</div><script>alert(1)</script> for better &origin &or;der,<div style=\"\">&nbsp;</div> for better &origin &or;der",
			"<div style=\"\">&nbsp;</div><script>alert(1)</script> for better &gtme &gt;o,<div style=\"\">&nbsp;</div> for better &gtme &gt;o",
			"<div style=\"\">&nbsp;</div><script>alert(1)</script> for better my&language &lang;uage,<div style=\"\">&nbsp;</div> for better my&language &lang;uage"})
	final void testCleanFirstHtmlEntities(String value, String expected) {
		assertThat(ESAPI.encoder().decodeForHTML(sanitizer.clean(value))).isEqualTo(expected);
	}

	@ParameterizedTest
	@CsvSource({"<div style=\"\">&nbsp;</div><script>alert(1)</script> for better &origin &or;der,<div style=\"\">&nbsp;</div> for better &origin &or;der",
			"<div style=\"\">&nbsp;</div><script>alert(1)</script> for better &gtme &gt;o,<div style=\"\">&nbsp;</div> for better &gtme &gt;o",
			"<div style=\"\">&nbsp;</div><script>alert(1)</script> for better my&language &lang;uage,<div style=\"\">&nbsp;</div> for better my&language &lang;uage"})
	final void testDecodeFirstHtmlEntities(String value, String expected) {
		assertThat(sanitizer.clean(ESAPI.encoder().decodeForHTML(value))).isEqualTo(expected);
	}
}
