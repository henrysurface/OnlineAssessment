require 'benchmark'
class Trie
    attr_accessor :direction_protocol, :ports, :children
    def initialize
        @direction_protocol = []
        @ports = []
        @children = Hash.new
    end
    
    def insert(dir, proto, ports)
        @direction_protocol << dir + proto if !@direction_protocol.include? dir + proto
        addPortRange(ports.to_i, ports.to_i)
    end

    def insert_ports_range(dir, proto, ports)
        @direction_protocol << dir + proto if !@direction_protocol.include? dir + proto
        range = ports.split('-')
        left = range[0].strip.to_i
        right = range[1].strip.to_i
        # puts right
        addPortRange(left, right);
    end

    def addPortRange(left, right)
        
        if @ports.empty? || @ports[-1].end < left
            @ports << Interval.new(left, right)
        else
            low = -1
            high = @ports.length - 1
            while low != high - 1
                mid = low + (high - low) / 2
                if(@ports[mid].end >= left) 
                    high = mid
                else 
                    low = mid
                end
            end
            if @ports[high].start < left
                @ports.insert(high + 1, Interval.new(left, right))
            else 
                @ports.insert(high, Interval.new(left, right))
            end
            
            for i in high...@ports.length-2
                first = @ports[i]
                second = @ports[i + 1]
                if first.nil? or second.nil?
                    break
                end
                if first.end >= second.start
                    first.end = [first.end, second.end].max
                    @ports.delete_at(i + 1)
                else 
                    break
                end
            end
        end
        # @ports.each do |p|
        #     puts p.start, p.end
        # end
    end

    def queryPorts(port)
        # @ports.each do |p|
        #     puts p.start, p.end
        # end
        if(@ports.length == 0 || @ports[0].start > port || @ports[-1].end < port) 
            return false;
        end

        low = 0
        high = @ports.length
        while low != high - 1
            mid = low + (high - low) / 2
            if(@ports[mid].start <= port) 
                low = mid
            else 
                high = mid
            end
        end
        # puts @ports[low].end
        return @ports[low].end >= port;
    end

end

class Interval
    attr_accessor :start, :end
    def initialize(left, right)
        @start = left
        @end = right
    end
    def start
        @start
    end
    def end
        @end
    end
end

class Firewall
    attr_accessor :root, :direction, :protocol, :ports
    def initialize(path)
        rules = File.read(path).split("\n")
        trie = Trie.new
        @root = trie
        rules.each do |rule|
            node = rule.split(",")
            @direction = node[0]
            @protocol = node[1]
            @ports = node[2]
            ip = node[3]
            if(ip.include? "-")
                allow_range_ip(ip , trie)
            else
                allow_singal_ip(ip , trie)
            end
        end
    end

    def allow_range_ip(ip , trie)
        ip_range = ip.split("-")
        ip_range_start = ip_range[0].split(".")
        ip_range_end = ip_range[1].split(".")
        # ip_range_end[0][0] = ''
        first_start_ip = ip_range_start[0].strip.to_i
        first_end_ip = ip_range_end[0].strip.to_i+1
        insert_ip_recursive(trie, 0, first_start_ip, first_end_ip ,ip_range_start, ip_range_end)
    end

    def insert_ip_recursive(trie, digit, digit_lower, digit_upper ,ip_range_start, ip_range_end)
        if digit == 4
            return
        end
        digit = digit+1
        second_start_ip = ip_range_start[digit].to_i
        second_end_ip = ip_range_end[digit].to_i+1
        # puts digit_lower, digit_upper
        for j in digit_lower...digit_upper
            cur_trie = insert_ip_digit(j, trie)
            next_lower = 0
            next_uppper = 256
            if j == digit_lower
                next_lower = second_start_ip
            end
            if j == digit_upper-1
                next_uppper = second_end_ip
            end
            # puts next_start_ip,next_end_ip
            insert_ip_recursive(cur_trie, digit, next_lower, next_uppper ,ip_range_start, ip_range_end)
        end
    end

    def insert_ip_digit(digit, trie)
        if(ports.include? "-")
            trie.insert_ports_range(@direction, @protocol, @ports)
        else
            trie.insert(@direction, @protocol, @ports)
        end
        #puts digit, trie.direction
        if trie.children[digit].nil?
            next_trie = Trie.new
            trie.children[digit] = next_trie 
            trie= next_trie
        else
            trie = trie.children[digit]
        end
        
        trie
    end

    def allow_singal_ip(ip , trie)
        ip_digits = ip.split(".")
        ip_digits.each do |digit|
            trie = insert_ip_digit(digit.to_i, trie)
        end
    end

    def accept_packet(dir, protocol, port, ip)
        flag = false
        node = @root
        ip_digits = ip.split(".")
        puts "#{dir},#{protocol},#{port},#{ip}"
        ip_digits.each do |digit|
            # puts digit
            # puts node.direction_protocol.include? dir+protocol
            # puts dir+protocol
            # puts node.direction_protocol
            # puts node.queryPorts(port.to_i)
            # node.ports.each do |p|
            #      puts p.start, p.end
            # end
            # puts node.children.include? digit.to_i
            # puts node.children.keys.first.to_s
            # puts "------"
            
            if node.direction_protocol.include? dir+protocol and node.queryPorts(port.to_i) and node.children.include? digit.to_i
                flag = true
                node = node.children[digit.to_i]
            else
                flag = false
                break
            end
        end
        puts flag
    end
end


fw = Firewall.new("/Users/henry/Documents/programming/ruby/path.csv")

puts "Query time of each request."
Benchmark.bm do |x|
    x.report{fw.accept_packet("inbound", "tcp", 81, "192.168.1.2")}
end

puts "---------------------------------"
puts ""
puts "Test for the rule with singal port and ip address."
fw.accept_packet("inbound", "tcp", 80, "192.168.1.2")

puts ""
puts "Test for the rule with the singal port and the range of ip address."
fw.accept_packet("inbound", "udp", 53, "192.168.2.1")

puts ""
puts "Test for the rule with the range of port and the singal ip address."
fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11")

puts ""
puts "Test for false case of wrang port."
fw.accept_packet("inbound", "tcp", 81, "192.168.1.2")

puts ""
puts "Test for wrang ip and port."
fw.accept_packet("inbound", "udp", 24, "52.12.48.92")

puts ""
puts "Test for the rule for adding range ip and port"
puts "Edge of port and ip"
fw.accept_packet("outbound", "tcp", 2100, "192.168.15.0")

fw.accept_packet("outbound", "tcp", 3000, "192.168.16.3")
puts "Mid of port and ip"
fw.accept_packet("outbound", "tcp", 2500, "192.168.15.100")
puts "Overlaping of port and ip from different rules"
fw.accept_packet("outbound", "tcp", 3000, "192.168.16.20")
puts "false case of port"
fw.accept_packet("outbound", "tcp", 3001, "192.168.16.3")
puts "Direction and port combination test: false case"
fw.accept_packet("outbound", "udp", 30, "192.168.1.2")