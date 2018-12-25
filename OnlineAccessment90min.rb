class Trie
    attr_accessor :direction, :protocol, :ports, :children
    def initialize
        @direction = []
        @protocol = []
        @ports = []
        @children = Hash.new
    end
    
    def insert(dir, proto, ports)
        @direction << dir if !@direction.include? dir
        @protocol << proto if !@protocol.include? proto
        addPortRange(ports.to_i, ports.to_i)
    end

    def insert_ports_range(dir, proto, ports)
        @direction << dir if !@direction.include? dir
        @protocol << proto if !@protocol.include? proto
        range = ports.split('-')
        range[1][0] = ''
        left = range[0].to_i
        right = range[1].to_i
        
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
                if first.end >= second.start
                    first.end = [first.end, second.end].max
                    @ports.delete_at(i + 1)
                else 
                    break
                end
            end
        end
        @ports.each do |p|
            puts p.start, p.end
        end
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
    attr_accessor :root
    def initialize(path)
        rules = File.read(path).split("\n")
        trie = Trie.new
        @root = trie
        rules.each do |rule|
            node = rule.split(",")
            direction = node[0]
            protocol = node[1]
            ports = node[2]
            ip = node[3]
            if(ip.include? "-")
                allow_range_ip(direction, protocol, ports, ip , trie)
            else
                allow_singal_ip(direction, protocol, ports, ip , trie)
            end
        end
    end

    def allow_range_ip(direction, protocol, ports, ip , trie)
        ip_range = ip.split("-")
        ip_range_start = ip_range[0].split(".")
        ip_range_end = ip_range[1].split(".")
        ip_range_end[0][0] = ''
        for i in 0..3
            start_ip = ip_range_start[i].to_i
            end_ip = ip_range_end[i].to_i+1
            # puts start_ip, end_ip
            for j in start_ip...end_ip
                puts j
                if(ports.include? "-")
                    trie.insert_ports_range(direction, protocol, ports)
                else
                    trie.insert(direction, protocol, ports)
                end
                
                if trie.children[j].nil?
                    puts "min"
                    next_trie = Trie.new
                    trie.children[j] = next_trie 
                    trie= next_trie
                else
                    puts "add"
                    trie = trie.children[j]
                end
            end
        end
    end

    def allow_singal_ip(direction, protocol, ports, ip , trie)
        ip_digits = ip.split(".")
        ip_digits.each do |digit|
            if(ports.include? "-")
                trie.insert_ports_range(direction, protocol, ports)
            else
                trie.insert(direction, protocol, ports)
            end
            if trie.children[digit].nil?
                next_trie = Trie.new
                trie.children[digit] = next_trie 
                trie= next_trie
            else
                trie = trie.children[digit]
            end
            
        end
    end

    def accept_packet(dir, protocol, port, ip)
        flag = false
        node = @root
        ip_digits = ip.split(".")
        ip_digits.each do |digit|
            # puts digit
            # puts node.direction.include? dir
            # puts node.direction
            # puts node.protocol.include? protocol
            # puts node.protocol
            # puts node.queryPorts(port.to_i)
            # puts node.ports[0].start
            # puts node.children.include? digit
            # puts "------"

            if node.direction.include? dir and node.protocol.include? protocol and node.queryPorts(port.to_i) and node.children.include? digit
                flag = true
                node = node.children[digit]
            else
                flag = false
                break
            end
        end
        puts flag
    end
end

fw = Firewall.new("your path file")


# fw.accept_packet("inbound", "tcp", 80, "192.168.1.2")

fw.accept_packet("inbound", "udp", 53, "192.168.2.1")

# fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11")

# fw.accept_packet("inbound", "tcp", 81, "192.168.1.2")

# fw.accept_packet("inbound", "udp", 24, "52.12.48.92")