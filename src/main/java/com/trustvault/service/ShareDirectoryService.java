package com.trustvault.service;

import com.trustvault.dto.ShareCandidateResponse;
import com.trustvault.entity.User;
import com.trustvault.entity.UserStatus;
import com.trustvault.repository.UserRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Address-book lookup for the document-sharing modal.
 *
 * <p>The owner has to name a recipient by email, and typing an exact address from memory is both
 * error-prone and a source of failed grants. This service answers with a short, filtered list of
 * <em>active</em> identities so the modal can offer them as suggestions.</p>
 *
 * <p>Exposure is bounded on purpose: at most {@link #MAX_RESULTS} rows, only the three display
 * fields, never the caller's own identity, and never a deactivated account (sharing with an
 * offboarded user would create a grant that the status filter rejects on first use).</p>
 */
@Service
public class ShareDirectoryService {

    /** Hard ceiling on suggestions returned per keystroke. */
    private static final int MAX_RESULTS = 8;

    /** Longer input is truncated: an email address never needs more than this. */
    private static final int MAX_TERM_LENGTH = 64;

    private final UserRepository userRepository;

    public ShareDirectoryService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Transactional(readOnly = true)
    public List<ShareCandidateResponse> suggest(String requesterUserId, String rawQuery) {
        String term = rawQuery == null ? "" : rawQuery.trim();
        if (term.length() > MAX_TERM_LENGTH) {
            term = term.substring(0, MAX_TERM_LENGTH);
        }
        // Wildcards are stripped rather than escaped: the query is a plain substring search, and a
        // caller-supplied '%' must never widen it into a registry dump.
        term = term.replace("%", "").replace("_", "").replace("\\", "");
        String pattern = "%" + term.toLowerCase(Locale.ROOT) + "%";

        List<User> matches = userRepository.searchActiveShareCandidates(
                UserStatus.ACTIVE, requesterUserId, pattern, PageRequest.of(0, MAX_RESULTS));

        List<ShareCandidateResponse> candidates = new ArrayList<>(matches.size());
        for (User user : matches) {
            candidates.add(new ShareCandidateResponse(
                    user.getId(),
                    user.getEmail(),
                    user.getFullName(),
                    user.getRole() != null ? user.getRole().name() : null));
        }
        return candidates;
    }
}
