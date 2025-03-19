package com.ahmed.AhmedSpring.doa;

import com.ahmed.AhmedSpring.entities.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TokenRepo extends JpaRepository<Token, Integer> {

    // method to help us to get the valid tokens for specific user
    @Query("select t from Token t inner join User u on t.u.id=u.id " +
            " where u.id=:id and (t.expired=false or t.revoked=false)" )
    List<Token> findAllValidTokenByUserId(int id);


    // finding the token by the token itself
    Optional<Token> findByToken(String token);
}
