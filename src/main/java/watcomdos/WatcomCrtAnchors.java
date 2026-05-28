// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Emily "TTG" Banerjee <prs.ttg+dedagger@pm.me>

package watcomdos;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

final class WatcomCrtAnchors {
	private WatcomCrtAnchors() {}

	static final Set<String> USER_CODE_ANCHORS = Collections.unmodifiableSet(
			new HashSet<>(Arrays.asList(
					"__cstart_",
					"main_",
					"entry",
					"_entry",
					"start",
					"_start",
					"_mainCRTStartup")));
}
