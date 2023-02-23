package com.C9group34.socialnetworkproject.repository;

import com.C9group34.socialnetworkproject.models.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Integer> {
}
