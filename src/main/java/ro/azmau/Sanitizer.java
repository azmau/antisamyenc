package ro.azmau;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.CleanResults;
import org.owasp.validator.html.Policy;
import org.owasp.validator.html.PolicyException;
import org.owasp.validator.html.ScanException;

public class Sanitizer {
	private final AntiSamy		antiSamy;

	public Sanitizer() {

		URL realPath = Sanitizer.class.getResource("/antisamy.xml");

		try (InputStream openStream = realPath.openStream()) {
			Policy policy = Policy.getInstance(openStream);
			antiSamy = new AntiSamy(policy);
		}
		catch (PolicyException | IOException e) {
			throw new IllegalStateException("Error during creating instance for Sanitizer", e);
		}
	}

	public String clean(String refEntry) {
		CleanResults cr;
		try {
			cr = antiSamy.scan(refEntry);
		}
		catch (ScanException | PolicyException e) {
			throw new RuntimeException(String.format("Error during scanning entry: %s", refEntry), e);
		}

		return cr.getCleanHTML();
	}

}
