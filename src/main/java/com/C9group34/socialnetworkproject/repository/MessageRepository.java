package com.C9group34.socialnetworkproject.repository;

import com.C9group34.socialnetworkproject.models.Message;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MessageRepository extends JpaRepository<Message, Integer> {
}
