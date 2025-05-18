package com.bezkoder.spring.security.jwt.controllers;

import com.bezkoder.spring.security.jwt.exception.StandardException;
import com.bezkoder.spring.security.jwt.exception.TokenRefreshException;
import com.bezkoder.spring.security.jwt.models.RefreshToken;
import com.bezkoder.spring.security.jwt.models.User;
import com.bezkoder.spring.security.jwt.payload.request.EnrollRequest;
import com.bezkoder.spring.security.jwt.payload.request.LoginRequest;
import com.bezkoder.spring.security.jwt.payload.request.SignupRequest;
import com.bezkoder.spring.security.jwt.payload.request.TokenRefreshRequest;
import com.bezkoder.spring.security.jwt.payload.response.LoginSuccessResponse;
import com.bezkoder.spring.security.jwt.payload.response.MessageResponse;
import com.bezkoder.spring.security.jwt.payload.response.TokenRefreshResponse;
import com.bezkoder.spring.security.jwt.repository.RoleRepository;
import com.bezkoder.spring.security.jwt.repository.UserRepository;
import com.bezkoder.spring.security.jwt.security.jwt.JwtUtils;
import com.bezkoder.spring.security.jwt.security.services.RefreshTokenService;
import com.bezkoder.spring.security.jwt.security.services.UserDetailsImpl;
import com.bezkoder.spring.security.jwt.security.services.api.TotpManager;
import dev.samstevens.totp.exceptions.QrGenerationException;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    RefreshTokenService refreshTokenService;

    @Autowired
    TotpManager totpManager;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) throws QrGenerationException {

        Authentication authentication = authenticationManager
            .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        User user = userDetails.getUser();

        if (user.isDisabled()) {
            throw new StandardException(HttpStatus.UNAUTHORIZED, "User is disabled. Contact Administrator");
        }

        LoginSuccessResponse.LoginSuccessResponseBuilder loginSuccessResponseBuilder =
            LoginSuccessResponse.builder()
                .email(userDetails.getEmail())
                .id(userDetails.getId())
                .username(userDetails.getUsername())
                .isMFAEnabled(user.isMFAEnabled())
                .isMFAEnrolled(user.isMFAEnrolled());

        if (user.isMFAEnabled()) {
            loginSuccessResponseBuilder.token( jwtUtils.generateMFAToken(user));
            if (!user.isMFAEnrolled()) {
                user.setMFASecretKey(totpManager.generateSecretKey());
                userRepository.save(user);
                loginSuccessResponseBuilder.MFAQRCode(totpManager.getQRCode(user.getMFASecretKey()));
            }
        } else {
            loginSuccessResponseBuilder.token( jwtUtils.generateJwtToken(user));
            loginSuccessResponseBuilder.roles(userDetails.getAuthorities().stream().map(item -> item.getAuthority())
                .collect(Collectors.toList()));
            loginSuccessResponseBuilder.refreshToken(refreshTokenService.createRefreshToken(userDetails.getId()).getToken());
        }

        return ResponseEntity.ok(loginSuccessResponseBuilder.build());
    }

    @PostMapping("/signup")
    @PreAuthorize("hasRole('CREATE_USERS')")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) throws URISyntaxException {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            throw new StandardException(HttpStatus.BAD_REQUEST, "Error: Username is already taken");
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            throw new StandardException(HttpStatus.BAD_REQUEST, "Error: Email is already taken");
        }

        User user = userRepository.save(
            User.builder()
                .username(signUpRequest.getUsername())
                .password(encoder.encode(signUpRequest.getPassword()))
                .email(signUpRequest.getEmail())
                .isMFAEnabled(signUpRequest.isEnableMFA())
                .role(roleRepository.findById(signUpRequest.getRoleId())
                    .orElseThrow(() -> new StandardException(HttpStatus.NOT_FOUND, "Role not found")))
                .build());

        return ResponseEntity.created(new URI("/users/" + user.getId())).body(user);
    }

    @PostMapping("/enrollmfa")
    @PreAuthorize("hasRole('MFATOKEN')")
    public ResponseEntity<?> enrollMFA(@Valid @RequestBody EnrollRequest enrollRequest) {

        UserDetailsImpl userDetails = (UserDetailsImpl) SecurityContextHolder.getContext()
            .getAuthentication().getPrincipal();

        User user = userRepository.findByUsername( userDetails.getUser().getUsername())
            .orElseThrow(() -> new StandardException(HttpStatus.NOT_FOUND, "User not found"));

        if (user.isDisabled()) {
            throw new StandardException(HttpStatus.UNAUTHORIZED, "User is disabled. Contact Administrator");
        }

        if (totpManager.verifyTotp(enrollRequest.getTotp(), user.getMFASecretKey())) {

            user.setMFAEnrolled(true);
            user = userRepository.save(user);

            return ResponseEntity.ok(getLoginSuccessResponseFromUser(user));

        } else {
            throw new StandardException(HttpStatus.UNAUTHORIZED, "Invalid OTP");
        }

    }
    @PostMapping("/verifymfa")
    @PreAuthorize("hasRole('MFATOKEN')")
    public ResponseEntity<?> verifyMFA(@Valid @RequestBody EnrollRequest enrollRequest) {

        UserDetailsImpl userDetails = (UserDetailsImpl) SecurityContextHolder.getContext()
            .getAuthentication().getPrincipal();

        User user = userRepository.findByUsername( userDetails.getUser().getUsername())
            .orElseThrow(() -> new StandardException(HttpStatus.NOT_FOUND, "User not found"));

        if (user.isDisabled()) {
            throw new StandardException(HttpStatus.UNAUTHORIZED, "User is disabled. Contact Administrator");
        }

        if (!user.isMFAEnrolled()) {
            throw new StandardException(HttpStatus.UNAUTHORIZED, "2FA enrollment is not configured yet");
        }

        if (totpManager.verifyTotp(enrollRequest.getTotp(), user.getMFASecretKey())) {
            return ResponseEntity.ok(getLoginSuccessResponseFromUser(user));
        } else {
            throw new StandardException(HttpStatus.UNAUTHORIZED, "Invalid OTP");
        }
    }


    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshtoken(@Valid @RequestBody TokenRefreshRequest request) {

        return refreshTokenService.findByToken(request.getRefreshToken())
            .map(refreshTokenService::verifyExpiration)
            .map(RefreshToken::getUser)
            .map(user -> {
                String token = jwtUtils.generateJwtToken(user);
                return ResponseEntity.ok(new TokenRefreshResponse(token, request.getRefreshToken()));
            }).orElseThrow(() -> new TokenRefreshException(request.getRefreshToken(),
                "Invalid Refresh token"));
    }

    @PostMapping("/signout")
    public ResponseEntity<?> logoutUser() {
        UserDetailsImpl userDetails = (UserDetailsImpl) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Long userId = userDetails.getId();
        refreshTokenService.deleteByUserId(userId);
        return ResponseEntity.ok(new MessageResponse("Log out successful!"));
    }

    private LoginSuccessResponse getLoginSuccessResponseFromUser(User user) {
        return  LoginSuccessResponse.builder()
            .email(user.getEmail())
            .id(user.getId())
            .username(user.getUsername())
            .isMFAEnabled(user.isMFAEnabled())
            .isMFAEnrolled(user.isMFAEnrolled())
            .token(jwtUtils.generateJwtToken(user))
            .build();
    }

}
