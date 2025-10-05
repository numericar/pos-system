package com.sentinels.pos.services.impl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.sentinels.pos.entities.User;
import com.sentinels.pos.repositories.UserRepository;

/*
    เมื่อเราทำการ implements UserDetailsService แล้ว 
    ระบบสร้าง user อัตโนมัติของ spring จะถูกปิดใช้งาน เนื่องจาก เราจะจัดการ user เองแล้ว
 */
@Service
public class CustomUserDetailsServiceImpl implements UserDetailsService {

    private UserRepository userRepository;

    public CustomUserDetailsServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> userOptional = this.userRepository.findByEmail(username);

        if (userOptional.isEmpty()) {
            throw new UsernameNotFoundException("User not found");
        }

        User user = userOptional.get();

        GrantedAuthority authority = new SimpleGrantedAuthority(user.getRole().name());

        Collection<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(authority);

        return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), authorities);
    }

}
