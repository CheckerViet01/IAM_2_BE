package com.iam.security;

import com.iam.entity.User;
import com.iam.exception.AppException;
import com.iam.exception.ErrorCode;
import com.iam.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(usernameOrEmail)
                .or(() -> userRepository.findByEmail(usernameOrEmail))
                .orElseThrow(() -> new UsernameNotFoundException("Không tìm thấy người dùng: " + usernameOrEmail));

        if (user.isLocked()) {
            throw new AppException(ErrorCode.USER_LOCKED);
        }
        if (user.isDeleted()) {
            throw new AppException(ErrorCode.USER_DELETED);
        }

        return CustomUserDetails.build(user);
    }
}
